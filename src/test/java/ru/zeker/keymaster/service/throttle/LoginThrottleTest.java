package ru.zeker.keymaster.service.throttle;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import ru.zeker.keymaster.config.LoginThrottleConfig;
import ru.zeker.keymaster.exception.ErrorCode;
import ru.zeker.keymaster.exception.KeyMasterException;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class LoginThrottleTest {

    private static final String IP = "203.0.113.10";
    private static final String OTHER_IP = "198.51.100.20";
    private static final String LOGIN = "admin";

    private MutableClock clock;
    private LoginThrottleConfig.IpLimit ipLimit;
    private LoginThrottleConfig.LoginLimit loginLimit;
    private LoginThrottleConfig.PairLimit pairLimit;
    private LoginThrottle throttle;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        ipLimit = mock(LoginThrottleConfig.IpLimit.class);
        loginLimit = mock(LoginThrottleConfig.LoginLimit.class);
        pairLimit = mock(LoginThrottleConfig.PairLimit.class);

        LoginThrottleConfig config = mock(LoginThrottleConfig.class);
        when(config.ipLimit()).thenReturn(ipLimit);
        when(config.loginLimit()).thenReturn(loginLimit);
        when(config.pairLimit()).thenReturn(pairLimit);

        throttle = new LoginThrottle(config, clock);
    }

    @Test
    void concurrentAcquiresCannotExceedPairLimit() throws Exception {
        int limit = 5;
        int attempts = 50;
        setLimits(1_000, Duration.ofMinutes(1), 1_000, Duration.ofMinutes(15), limit, Duration.ofMinutes(5));

        ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
        CountDownLatch start = new CountDownLatch(1);

        try {
            List<Future<Boolean>> results = new ArrayList<>(attempts);

            for (int i = 0; i < attempts; i++) {
                results.add(executor.submit(() -> {
                    start.await();

                    try {
                        throttle.acquire(IP, LOGIN);
                        return true;
                    } catch (KeyMasterException e) {
                        return false;
                    }
                }));
            }

            start.countDown();

            long accepted = 0;
            for (Future<Boolean> result : results) {
                if (result.get()) {
                    accepted++;
                }
            }

            assertEquals(limit, accepted);
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void rejectsWhenPairLimitIsExceededWithRetryAfterForThatWindow() {
        setLimits(100, Duration.ofMinutes(1), 100, Duration.ofMinutes(15), 2, Duration.ofMinutes(5));

        throttle.acquire(IP, LOGIN);
        throttle.acquire(IP, LOGIN);
        clock.advance(Duration.ofMinutes(1));

        KeyMasterException exception = assertThrows(
                KeyMasterException.class,
                () -> throttle.acquire(IP, LOGIN)
        );

        assertEquals(ErrorCode.TOO_MANY_REQUESTS, exception.getCode());
        assertEquals(Duration.ofMinutes(4), exception.getRetryAfter());
    }

    @Test
    void windowShiftAllowsLoginAgain() {
        setLimits(100, Duration.ofMinutes(1), 100, Duration.ofMinutes(15), 1, Duration.ofMinutes(1));

        throttle.acquire(IP, LOGIN);
        clock.advance(Duration.ofSeconds(15));

        KeyMasterException exception = assertThrows(
                KeyMasterException.class,
                () -> throttle.acquire(IP, LOGIN)
        );
        assertEquals(Duration.ofSeconds(45), exception.getRetryAfter());

        clock.advance(Duration.ofSeconds(45));

        assertDoesNotThrow(() -> throttle.acquire(IP, LOGIN));
    }

    @Test
    void successResetsLoginAndPairAndReturnsIpUnit() {
        setLimits(1, Duration.ofMinutes(1), 1, Duration.ofMinutes(15), 1, Duration.ofMinutes(5));

        throttle.acquire(IP, LOGIN).success();

        assertDoesNotThrow(() -> throttle.acquire(IP, LOGIN));
    }

    @Test
    void refundReturnsAllCounters() {
        setLimits(1, Duration.ofMinutes(1), 1, Duration.ofMinutes(15), 1, Duration.ofMinutes(5));

        throttle.acquire(IP, LOGIN).refund();

        assertDoesNotThrow(() -> throttle.acquire(IP, LOGIN));
    }

    @Test
    void failedPairReservationRollsBackIpAndLoginIncrements() {
        setLimits(1, Duration.ofSeconds(1), 1, Duration.ofSeconds(1), 1, Duration.ofMinutes(1));

        throttle.acquire(IP, LOGIN);
        clock.advance(Duration.ofSeconds(2));

        assertThrows(KeyMasterException.class, () -> throttle.acquire(IP, LOGIN));

        assertDoesNotThrow(() -> throttle.acquire(OTHER_IP, LOGIN));
    }

    @Test
    void countsCaseAndNfkcVariantsAsTheSameLogin() {
        setLimits(100, Duration.ofMinutes(1), 2, Duration.ofMinutes(15), 100, Duration.ofMinutes(5));

        throttle.acquire(IP, "Admin");
        throttle.acquire(IP, "ADMIN");

        KeyMasterException exception = assertThrows(
                KeyMasterException.class,
                () -> throttle.acquire(IP, "admin")
        );

        assertEquals(ErrorCode.TOO_MANY_REQUESTS, exception.getCode());
    }

    @Test
    void countsFullWidthLoginAsTheSameLogin() {
        setLimits(100, Duration.ofMinutes(1), 2, Duration.ofMinutes(15), 100, Duration.ofMinutes(5));

        throttle.acquire(IP, "admin");
        throttle.acquire(IP, "ａｄｍｉｎ");

        KeyMasterException exception = assertThrows(
                KeyMasterException.class,
                () -> throttle.acquire(IP, "ADMIN")
        );

        assertEquals(ErrorCode.TOO_MANY_REQUESTS, exception.getCode());
    }

    @Test
    void invalidLoginFormatReturns401AndDoesNotConsumeLoginCounter() {
        setLimits(10, Duration.ofMinutes(1), 1, Duration.ofMinutes(15), 10, Duration.ofMinutes(5));

        throttle.acquire(IP, LOGIN);

        KeyMasterException exception = assertThrows(
                KeyMasterException.class,
                () -> throttle.acquire(IP, "a".repeat(33))
        );

        assertEquals(ErrorCode.INVALID_CREDENTIALS, exception.getCode());
    }

    @Test
    void groupsIpv6BySixtyFourPrefix() {
        setLimits(1, Duration.ofMinutes(1), 100, Duration.ofMinutes(15), 100, Duration.ofMinutes(5));

        throttle.acquire("2001:db8:1::1", LOGIN);

        KeyMasterException exception = assertThrows(
                KeyMasterException.class,
                () -> throttle.acquire("2001:db8:1:0:ffff::2", LOGIN)
        );

        assertEquals(ErrorCode.TOO_MANY_REQUESTS, exception.getCode());
        assertDoesNotThrow(() -> throttle.acquire("2001:db8:2::1", LOGIN));
    }

    @Test
    void invalidIpSkipsIpCountersAndStillLimitsByLogin() {
        setLimits(1, Duration.ofMinutes(1), 2, Duration.ofMinutes(15), 100, Duration.ofMinutes(5));

        throttle.acquire("not-an-ip", LOGIN);
        throttle.acquire("not-an-ip", LOGIN);

        KeyMasterException exception = assertThrows(
                KeyMasterException.class,
                () -> throttle.acquire("not-an-ip", LOGIN)
        );

        assertEquals(ErrorCode.TOO_MANY_REQUESTS, exception.getCode());
        assertEquals(Duration.ofMinutes(15), exception.getRetryAfter());
    }

    @Test
    void missingIpSkipsIpCountersAndLimitsOnlyByLogin() {
        setLimits(1, Duration.ofMinutes(1), 2, Duration.ofMinutes(15), 1, Duration.ofMinutes(5));

        throttle.acquire(null, LOGIN);
        throttle.acquire(null, LOGIN);

        KeyMasterException exception = assertThrows(
                KeyMasterException.class,
                () -> throttle.acquire(null, LOGIN)
        );

        assertEquals(ErrorCode.TOO_MANY_REQUESTS, exception.getCode());
        assertNotNull(exception.getRetryAfter());
    }

    private void setLimits(
            int ipAttempts,
            Duration ipWindow,
            int loginAttempts,
            Duration loginWindow,
            int pairAttempts,
            Duration pairWindow
    ) {
        when(ipLimit.enabled()).thenReturn(true);
        when(ipLimit.maxAttempts()).thenReturn(ipAttempts);
        when(ipLimit.window()).thenReturn(ipWindow);

        when(loginLimit.maxAttempts()).thenReturn(loginAttempts);
        when(loginLimit.window()).thenReturn(loginWindow);

        when(pairLimit.maxAttempts()).thenReturn(pairAttempts);
        when(pairLimit.window()).thenReturn(pairWindow);
    }

    private static final class MutableClock extends Clock {

        private Instant instant;

        private MutableClock(Instant instant) {
            this.instant = instant;
        }

        void advance(Duration duration) {
            instant = instant.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }
}
