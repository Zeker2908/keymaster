package ru.zeker.keymaster.service.throttle;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import jakarta.enterprise.context.ApplicationScoped;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import ru.zeker.keymaster.config.LoginThrottleConfig;
import ru.zeker.keymaster.domain.Patterns;
import ru.zeker.keymaster.exception.ErrorCode;
import ru.zeker.keymaster.exception.KeyMasterException;
import ru.zeker.keymaster.exception.TooManyRequestsException;
import ru.zeker.keymaster.util.Secrets;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;

@Slf4j
@ApplicationScoped
public class LoginThrottle {

    private static final int MAX_LOGIN_LENGTH = 32;
    private static final Pattern LOGIN_KEY = Pattern.compile(Patterns.LOGIN);

    private static final Duration CACHE_EXPIRATION = Duration.ofMinutes(15);
    private static final long MAXIMUM_SIZE = 100_000;

    private final LoginThrottleConfig config;
    private final Clock clock;

    private final Cache<String, WindowCounter> ipAttempts = createCache();
    private final Cache<String, WindowCounter> loginAttempts = createCache();
    private final Cache<PairKey, WindowCounter> pairAttempts = createCache();

    /**
     * Caffeine обеспечивает атомарность операций с каждым счётчиком по отдельности,
     * но одна попытка входа затрагивает три счётчика. Блокировка гарантирует,
     * что операции резервирования, подтверждения и возврата выполняются атомарно
     * относительно друг друга.
     */
    private final ReentrantLock lock = new ReentrantLock();

    public LoginThrottle(LoginThrottleConfig config, Clock clock) {
        this.config = config;
        this.clock = clock;
    }

    /**
     * Резервирует одну попытку входа. Резервирование выполняется до проверки пароля,
     * чтобы параллельные запросы не могли одновременно увидеть пустой счётчик
     * и превысить установленный лимит.
     *
     * @throws KeyMasterException с кодом 429, если превышен любой из лимитов,
     *                            или с кодом 401, если логин имеет недопустимый формат
     *                            (такие попытки учитываются только в счётчике IP).
     */
    public Ticket acquire(String rawIp, String rawLogin) {
        String ipKey = normalizeIp(rawIp);
        boolean ipCounted = ipKey != null && config.ipLimit().enabled();

        if (config.ipLimit().enabled() && ipKey == null) {
            log.warn("Login throttle: client IP is missing or invalid; IP-based limits are skipped");
        }

        String loginKey = normalizeLogin(rawLogin);

        lock.lock();
        try {
            List<Reservation<?>> reservations = new ArrayList<>(3);

            try {
                Reservation<String> ipReservation = null;
                if (ipCounted) {
                    ipReservation = reserve(
                            ipAttempts,
                            ipKey,
                            config.ipLimit().maxAttempts(),
                            config.ipLimit().window(),
                            "ip"
                    );
                    reservations.add(ipReservation);
                }

                if (loginKey == null) {
                    throw new KeyMasterException(ErrorCode.INVALID_CREDENTIALS);
                }

                Reservation<String> loginReservation = reserve(
                        loginAttempts,
                        loginKey,
                        config.loginLimit().maxAttempts(),
                        config.loginLimit().window(),
                        "login"
                );
                reservations.add(loginReservation);

                Reservation<PairKey> pairReservation = null;
                if (ipCounted) {
                    pairReservation = reserve(
                            pairAttempts,
                            new PairKey(ipKey, loginKey),
                            config.pairLimit().maxAttempts(),
                            config.pairLimit().window(),
                            "ip_login"
                    );
                    reservations.add(pairReservation);
                }

                return new Ticket(ipReservation, loginReservation, pairReservation);
            } catch (LimitExceeded e) {
                for (int i = reservations.size() - 1; i >= 0; i--) {
                    reservations.get(i).decrement();
                }
                throw e.toException();
            }
        } finally {
            lock.unlock();
        }
    }

    private <K> Reservation<K> reserve(
            Cache<K, WindowCounter> cache,
            K key,
            int limit,
            Duration window,
            String scope
    ) {
        Instant now = clock.instant();
        WindowCounter counter = cache.getIfPresent(key);

        if (counter == null || counter.isExpired(now, window)) {
            counter = new WindowCounter(now, 0);
        }

        if (counter.attempts() >= limit) {
            throw new LimitExceeded(scope, remaining(counter, window, now));
        }

        cache.put(key, new WindowCounter(counter.windowStartedAt(), counter.attempts() + 1));

        return new Reservation<>(cache, key, counter.windowStartedAt());
    }

    private Duration remaining(WindowCounter counter, Duration window, Instant now) {
        Duration left = Duration.between(now, counter.windowStartedAt().plus(window));
        return left.isNegative() ? Duration.ZERO : left;
    }

    private static <K> Cache<K, WindowCounter> createCache() {
        return Caffeine.newBuilder()
                .maximumSize(MAXIMUM_SIZE)
                .expireAfterAccess(CACHE_EXPIRATION)
                .build();
    }

    private String normalizeLogin(String login) {
        if (login == null || login.length() > MAX_LOGIN_LENGTH) {
            return null;
        }

        String normalized = Secrets.normalize(login.trim().toLowerCase(Locale.ROOT));

        if (normalized.isEmpty()
                || normalized.length() > MAX_LOGIN_LENGTH
                || !LOGIN_KEY.matcher(normalized).matches()) {
            return null;
        }

        return Secrets.hash(normalized);
    }

    private String normalizeIp(String ip) {
        if (StringUtils.isBlank(ip)) {
            return null;
        }

        try {
            InetAddress address = InetAddress.ofLiteral(ip.trim());

            if (address instanceof Inet6Address) {
                return "v6:" + HexFormat.of().formatHex(address.getAddress(), 0, 8);
            }

            return "v4:" + address.getHostAddress();
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    public final class Ticket {

        private final Reservation<String> ipReservation;
        private final Reservation<String> loginReservation;
        private final Reservation<PairKey> pairReservation;
        private final AtomicBoolean settled = new AtomicBoolean();

        private Ticket(
                Reservation<String> ipReservation,
                Reservation<String> loginReservation,
                Reservation<PairKey> pairReservation
        ) {
            this.ipReservation = ipReservation;
            this.loginReservation = loginReservation;
            this.pairReservation = pairReservation;
        }

        /**
         * Успешный вход: сбрасывает счётчики логина и пары (IP, логин),
         * а также возвращает единицу, зарезервированную этим запросом,
         * в счётчик IP.
         */
        public void success() {
            if (!settled.compareAndSet(false, true)) {
                return;
            }

            lock.lock();
            try {
                loginReservation.invalidate();

                if (pairReservation != null) {
                    pairReservation.invalidate();
                }

                if (ipReservation != null) {
                    ipReservation.decrement();
                }
            } finally {
                lock.unlock();
            }
        }

        /**
         * Ошибка, не связанная с неверными учётными данными (503, 5xx, ошибки подписи):
         * такая попытка не подтверждает, что учётные данные неверны,
         * поэтому она не должна учитываться в лимитах.
         */
        public void refund() {
            if (!settled.compareAndSet(false, true)) {
                return;
            }

            lock.lock();
            try {
                loginReservation.decrement();

                if (pairReservation != null) {
                    pairReservation.decrement();
                }

                if (ipReservation != null) {
                    ipReservation.decrement();
                }
            } finally {
                lock.unlock();
            }
        }
    }

    private record Reservation<K>(Cache<K, WindowCounter> cache, K key, Instant windowStartedAt) {

        /**
         * Возвращает одну единицу счётчика только в том случае, если он всё ещё относится
         * к тому временному окну, в котором была зарезервирована попытка.
         * Это предотвращает уменьшение счётчика нового окна при позднем завершении запроса.
         */
        void decrement() {
            cache.asMap().computeIfPresent(key, (_, current) -> {
                if (!current.windowStartedAt().equals(windowStartedAt)) {
                    return current;
                }

                return current.attempts() <= 1
                        ? null
                        : new WindowCounter(current.windowStartedAt(), current.attempts() - 1);
            });
        }

        void invalidate() {
            cache.invalidate(key);
        }
    }

    private record PairKey(String ip, String loginHash) {
    }

    private record WindowCounter(Instant windowStartedAt, int attempts) {

        boolean isExpired(Instant now, Duration window) {
            return !now.isBefore(windowStartedAt.plus(window));
        }
    }

    private static final class LimitExceeded extends RuntimeException {

        private final String scope;
        private final Duration retryAfter;

        private LimitExceeded(String scope, Duration retryAfter) {
            super(null, null, false, false);
            this.scope = scope;
            this.retryAfter = retryAfter;
        }

        private KeyMasterException toException() {
            log.warn("Login rate limit exceeded: scope={}, retryAfter={}ms",
                    scope, retryAfter.toMillis());

            return new TooManyRequestsException(retryAfter);
        }
    }
}
