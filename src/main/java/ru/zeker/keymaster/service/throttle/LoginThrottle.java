package ru.zeker.keymaster.service.throttle;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Ticker;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import ru.zeker.keymaster.config.LoginThrottleConfig;
import ru.zeker.keymaster.exception.ErrorCode;
import ru.zeker.keymaster.exception.KeyMasterException;
import ru.zeker.keymaster.exception.TooManyRequestsException;
import ru.zeker.keymaster.service.LoginNormalizer;
import ru.zeker.keymaster.util.Secrets;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

@Slf4j
@ApplicationScoped
public class LoginThrottle {

    /**
     * Старое значение срока жизни кэша. Оставляем его как нижнюю границу,
     * чтобы короткие окна не меняли привычный профиль памяти.
     */
    private static final Duration MIN_CACHE_EXPIRATION = Duration.ofMinutes(15);
    private static final Duration MISSING_IP_LOG_INTERVAL = Duration.ofMinutes(1);
    private static final long MAXIMUM_SIZE = 100_000;

    private final LoginThrottleConfig config;
    private final Clock clock;

    private final Cache<String, WindowCounter> ipAttempts;
    private final Cache<String, WindowCounter> loginAttempts;
    private final Cache<PairKey, WindowCounter> pairAttempts;

    private final AtomicReference<Instant> lastMissingIpWarning = new AtomicReference<>();

    /**
     * Caffeine обеспечивает атомарность операций с каждым счётчиком по отдельности,
     * но одна попытка входа затрагивает три счётчика. Блокировка гарантирует,
     * что операции резервирования, подтверждения и возврата выполняются атомарно
     * относительно друг друга.
     */
    private final ReentrantLock lock = new ReentrantLock();

    @Inject
    public LoginThrottle(LoginThrottleConfig config, Clock clock) {
        this(config, clock, Ticker.systemTicker());
    }

    LoginThrottle(LoginThrottleConfig config, Clock clock, Ticker ticker) {
        this.config = config;
        this.clock = clock;

        Duration cacheExpiration = resolveCacheExpiration(config);
        this.ipAttempts = createCache(cacheExpiration, ticker);
        this.loginAttempts = createCache(cacheExpiration, ticker);
        this.pairAttempts = createCache(cacheExpiration, ticker);
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
        boolean hasIp = ipKey != null;
        boolean ipCounted = hasIp && config.ipLimit().enabled();

        if (config.ipLimit().enabled() && !hasIp) {
            warnMissingIp();
        }

        String loginKey = LoginNormalizer.normalize(rawLogin);
        if (loginKey != null) {
            loginKey = Secrets.hash(loginKey);
        }

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
                            config.ipLimit().window()
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
                        config.loginLimit().window()
                );
                reservations.add(loginReservation);

                Reservation<PairKey> pairReservation = null;
                if (hasIp) {
                    pairReservation = reserve(
                            pairAttempts,
                            new PairKey(ipKey, loginKey),
                            config.pairLimit().maxAttempts(),
                            config.pairLimit().window()
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
            Duration window
    ) {
        Instant now = clock.instant();
        WindowCounter counter = cache.getIfPresent(key);

        if (counter == null || counter.isExpired(now, window)) {
            counter = new WindowCounter(now, 0);
        }

        if (counter.attempts() >= limit) {
            throw new LimitExceeded(remaining(counter, window, now));
        }

        cache.put(key, new WindowCounter(counter.windowStartedAt(), counter.attempts() + 1));

        return new Reservation<>(cache, key, counter.windowStartedAt());
    }

    private Duration remaining(WindowCounter counter, Duration window, Instant now) {
        Duration left = Duration.between(now, counter.windowStartedAt().plus(window));
        return left.isNegative() ? Duration.ZERO : left;
    }

    private void warnMissingIp() {
        Instant now = clock.instant();
        Instant last = lastMissingIpWarning.get();

        if (last != null && Duration.between(last, now).compareTo(MISSING_IP_LOG_INTERVAL) < 0) {
            return;
        }

        if (lastMissingIpWarning.compareAndSet(last, now)) {
            log.warn("Login throttle: client IP is missing or invalid; IP-based limits are skipped");
        }
    }

    private static Duration resolveCacheExpiration(LoginThrottleConfig config) {
        Duration ipWindow = requirePositiveWindow(config.ipLimit().window(), "ip-limit.window");
        Duration loginWindow = requirePositiveWindow(config.loginLimit().window(), "login-limit.window");
        Duration pairWindow = requirePositiveWindow(config.pairLimit().window(), "pair-limit.window");

        Duration maxWindow = ipWindow;
        if (loginWindow.compareTo(maxWindow) > 0) {
            maxWindow = loginWindow;
        }
        if (pairWindow.compareTo(maxWindow) > 0) {
            maxWindow = pairWindow;
        }

        Duration expiration = maxWindow.compareTo(MIN_CACHE_EXPIRATION) >= 0
                ? maxWindow
                : MIN_CACHE_EXPIRATION;

        if (expiration.compareTo(maxWindow) < 0) {
            throw new IllegalStateException(
                    "Login throttle cache expiration must not be shorter than the largest configured window");
        }

        return expiration;
    }

    private static Duration requirePositiveWindow(Duration window, String name) {
        if (window == null || window.isZero() || window.isNegative()) {
            throw new IllegalStateException("Login throttle " + name + " must be positive");
        }
        return window;
    }

    private static <K> Cache<K, WindowCounter> createCache(Duration expiration, Ticker ticker) {
        return Caffeine.newBuilder()
                .maximumSize(MAXIMUM_SIZE)
                .expireAfterWrite(expiration)
                .ticker(ticker)
                .build();
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

        private final Duration retryAfter;

        private LimitExceeded(Duration retryAfter) {
            super(null, null, false, false);
            this.retryAfter = retryAfter;
        }

        private KeyMasterException toException() {
            return new TooManyRequestsException(retryAfter);
        }
    }
}
