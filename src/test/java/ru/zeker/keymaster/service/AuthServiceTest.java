package ru.zeker.keymaster.service;

import com.nimbusds.jwt.JWT;
import de.mkammerer.argon2.Argon2;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.smallrye.mutiny.Uni;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import ru.zeker.keymaster.config.LoginThrottleConfig;
import ru.zeker.keymaster.config.PasswordConfig;
import ru.zeker.keymaster.domain.context.RequestContext;
import ru.zeker.keymaster.domain.jwt.Subject;
import ru.zeker.keymaster.domain.key.SigningKeyData;
import ru.zeker.keymaster.dto.request.LoginRequest;
import ru.zeker.keymaster.dto.response.TokenResponse;
import ru.zeker.keymaster.exception.ErrorCode;
import ru.zeker.keymaster.exception.KeyMasterException;
import ru.zeker.keymaster.service.jwt.AccessTokenFactory;
import ru.zeker.keymaster.service.key.ActiveKeyResolver;
import ru.zeker.keymaster.service.metrics.LoginMetrics;
import ru.zeker.keymaster.service.password.PasswordHasher;
import ru.zeker.keymaster.service.throttle.LoginThrottle;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class AuthServiceTest {

    private static final String LOGIN = "admin";

    private PasswordHasher hasher;
    private PrincipalService principals;
    private ActiveKeyResolver resolver;
    private AccessTokenFactory tokenFactory;
    private LoginThrottleConfig.LoginLimit loginLimit;
    private SimpleMeterRegistry meterRegistry;
    private AuthService service;

    @BeforeEach
    void setUp() {
        LoginThrottleConfig.IpLimit ipLimit = mock(LoginThrottleConfig.IpLimit.class);
        loginLimit = mock(LoginThrottleConfig.LoginLimit.class);
        LoginThrottleConfig.PairLimit pairLimit = mock(LoginThrottleConfig.PairLimit.class);

        when(ipLimit.enabled()).thenReturn(true);
        when(ipLimit.maxAttempts()).thenReturn(1_000);
        when(ipLimit.window()).thenReturn(Duration.ofMinutes(1));
        when(loginLimit.maxAttempts()).thenReturn(1_000);
        when(loginLimit.window()).thenReturn(Duration.ofMinutes(15));
        when(pairLimit.maxAttempts()).thenReturn(1_000);
        when(pairLimit.window()).thenReturn(Duration.ofMinutes(5));

        LoginThrottleConfig config = mock(LoginThrottleConfig.class);
        when(config.ipLimit()).thenReturn(ipLimit);
        when(config.loginLimit()).thenReturn(loginLimit);
        when(config.pairLimit()).thenReturn(pairLimit);

        RequestContext requestContext = mock(RequestContext.class);
        when(requestContext.getClientIp()).thenReturn("203.0.113.10");
        when(requestContext.getRequestId()).thenReturn("test-request");

        PasswordConfig passwordConfig = mock(PasswordConfig.class);
        hasher = spy(new PasswordHasher(
                mock(Argon2.class),
                passwordConfig,
                mock(ExecutorService.class)
        ));
        principals = mock(PrincipalService.class);
        resolver = mock(ActiveKeyResolver.class);
        tokenFactory = mock(AccessTokenFactory.class);
        meterRegistry = new SimpleMeterRegistry();

        service = new AuthService(
                resolver,
                tokenFactory,
                principals,
                hasher,
                new LoginMetrics(meterRegistry),
                new LoginThrottle(config, Clock.systemUTC()),
                requestContext,
                Clock.systemUTC()
        );
    }

    @Test
    void nullPasswordIsRejectedWithoutCallingHasher() {
        assertRejectedWithoutHasher(null);
    }

    @Test
    void emptyPasswordIsRejectedWithoutCallingHasher() {
        assertRejectedWithoutHasher(new char[0]);
    }

    @Test
    void passwordLongerThanLimitIsRejectedWithoutCallingHasher() {
        assertRejectedWithoutHasher("a".repeat(129).toCharArray());
    }

    @Test
    void passwordLongerThanLimitAfterNfkcIsRejectedWithoutCallingHasher() {
        assertRejectedWithoutHasher("ﬀ".repeat(65).toCharArray());
    }

    @Test
    void invalidPasswordKeepsTheAttemptReserved() {
        when(loginLimit.maxAttempts()).thenReturn(1);

        assertRejectedWithoutHasher(new char[0]);

        KeyMasterException exception = assertThrows(
                KeyMasterException.class,
                () -> service.login(new LoginRequest(LOGIN, "Password123!".toCharArray()))
                        .await().indefinitely()
        );

        assertEquals(ErrorCode.TOO_MANY_REQUESTS, exception.getCode());
        verifyNoInteractions(hasher);
    }

    @Test
    void successfulLoginIncrementsSuccessMetric() {
        Subject subject = new Subject(UUID.randomUUID(), "$argon2id$hash", List.of("user"));
        char[] password = "Password123!".toCharArray();

        when(principals.getByLogin(LOGIN)).thenReturn(Uni.createFrom().item(subject));
        doReturn(Uni.createFrom().item(true)).when(hasher).verify(subject.secretHash(), password);

        JWT jwt = mock(JWT.class);
        when(jwt.serialize()).thenReturn("signed-token");
        when(resolver.activeKey()).thenReturn(Uni.createFrom().item(mock(SigningKeyData.class)));
        when(tokenFactory.issue(any(), eq(subject), any())).thenReturn(jwt);
        when(tokenFactory.ttl()).thenReturn(Duration.ofMinutes(15));

        TokenResponse response = service.login(new LoginRequest(LOGIN, password))
                .await().indefinitely();

        assertEquals("signed-token", response.accessToken());
        assertEquals(1.0, loginCount("success"));
        assertEquals(0.0, loginCount("failure"));
    }

    @Test
    void wrongPasswordIncrementsFailureMetric() {
        Subject subject = new Subject(UUID.randomUUID(), "$argon2id$hash", List.of("user"));
        char[] password = "WrongPassword!".toCharArray();

        when(principals.getByLogin(LOGIN)).thenReturn(Uni.createFrom().item(subject));
        doReturn(Uni.createFrom().item(false)).when(hasher).verify(subject.secretHash(), password);

        KeyMasterException exception = assertThrows(
                KeyMasterException.class,
                () -> service.login(new LoginRequest(LOGIN, password)).await().indefinitely()
        );

        assertEquals(ErrorCode.INVALID_CREDENTIALS, exception.getCode());
        assertEquals(1.0, loginCount("failure"));
        assertEquals(0.0, loginCount("success"));
    }

    private void assertRejectedWithoutHasher(char[] password) {
        KeyMasterException exception = assertThrows(
                KeyMasterException.class,
                () -> service.login(new LoginRequest(LOGIN, password)).await().indefinitely()
        );

        assertEquals(ErrorCode.INVALID_CREDENTIALS, exception.getCode());
        verifyNoInteractions(hasher);
        verifyNoInteractions(principals);
        assertEquals(1.0, loginCount("failure"));

        if (password != null) {
            assertArrayEquals(new char[password.length], password);
        }
    }

    private double loginCount(String result) {
        return meterRegistry.get("keymaster.auth.login")
                .tag("result", result)
                .counter()
                .count();
    }
}
