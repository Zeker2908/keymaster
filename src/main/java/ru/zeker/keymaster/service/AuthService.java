package ru.zeker.keymaster.service;

import com.nimbusds.jwt.JWT;
import io.quarkus.runtime.StartupEvent;
import io.quarkus.vertx.VertxContextSupport;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import ru.zeker.keymaster.domain.context.RequestContext;
import ru.zeker.keymaster.domain.jwt.Subject;
import ru.zeker.keymaster.dto.request.LoginRequest;
import ru.zeker.keymaster.dto.response.TokenResponse;
import ru.zeker.keymaster.exception.ErrorCode;
import ru.zeker.keymaster.exception.KeyMasterException;
import ru.zeker.keymaster.exception.TooManyRequestsException;
import ru.zeker.keymaster.service.jwt.AccessTokenFactory;
import ru.zeker.keymaster.service.key.ActiveKeyResolver;
import ru.zeker.keymaster.service.metrics.LoginMetrics;
import ru.zeker.keymaster.service.password.PasswordHasher;
import ru.zeker.keymaster.service.throttle.LoginThrottle;
import ru.zeker.keymaster.util.Secrets;

import java.time.Clock;
import java.time.Duration;
import java.util.UUID;

@Slf4j
@ApplicationScoped
@RequiredArgsConstructor
public class AuthService {

    private static final int MAX_PASSWORD_LENGTH = 128;

    private final ActiveKeyResolver resolver;
    private final AccessTokenFactory tokenFactory;
    private final PrincipalService principals;
    private final PasswordHasher hasher;
    private final LoginMetrics metrics;
    private final LoginThrottle throttle;
    private final RequestContext requestContext;
    private final Clock clock;

    private volatile String dummyHash;

    void onStart(@Observes StartupEvent e) throws Throwable {
        dummyHash = VertxContextSupport.subscribeAndAwait(
                () -> hasher.hash(UUID.randomUUID().toString().toCharArray()).ifNoItem()
                        .after(Duration.ofSeconds(30))
                        .fail()
        );
    }

    public Uni<TokenResponse> login(LoginRequest request) {
        LoginThrottle.Ticket ticket;

        try {
            ticket = throttle.acquire(requestContext.getClientIp(), request.login());
        } catch (TooManyRequestsException e) {
            log.debug("Login rate limit exceeded: requestId={}, retryAfter={}s",
                    requestContext.getRequestId(), retryAfterSeconds(e));
            return Uni.createFrom().failure(e);
        } catch (KeyMasterException e) {
            if (e.getCode() == ErrorCode.INVALID_CREDENTIALS) {
                metrics.failure();
            }
            return Uni.createFrom().failure(e);
        } catch (RuntimeException e) {
            return Uni.createFrom().failure(e);
        }

        if (!hasAcceptablePassword(request.password())) {
            metrics.failure();
            Secrets.wipe(request.password());
            return Uni.createFrom().failure(new KeyMasterException(ErrorCode.INVALID_CREDENTIALS));
        }

        return doLogin(request)
                .onItem().invoke(() -> {
                    ticket.success();
                    metrics.success();
                })
                .onFailure(failure -> !isInvalidCredentials(failure)).invoke(ticket::refund);
    }

    private Uni<TokenResponse> doLogin(LoginRequest request) {
        return principals.getByLogin(request.login())
                .chain(subject -> {
                    String hash = subject != null ? subject.secretHash() : dummyHash;
                    return hasher.verify(hash, request.password())
                            .chain(valid -> {
                                if (subject == null || !valid) {
                                    metrics.failure();
                                    log.warn("Login failed: userId={}", subject != null ? subject.userId() : null);

                                    return Uni.createFrom().failure(
                                            new KeyMasterException(ErrorCode.INVALID_CREDENTIALS)
                                    );
                                }

                                return issueTokens(subject);
                            });
                });
    }

    private Uni<TokenResponse> issueTokens(Subject subject) {
        return resolver.activeKey()
                .map(key -> {
                    JWT accessToken = tokenFactory.issue(key, subject, clock.instant());

                    log.info("Login succeeded: userId={}", subject.userId());

                    // TODO(этап 6): выпускать refresh-токен вместе с его хэшем,
                    //  ротацией и защитой от повторного использования.
                    return TokenResponse.of(accessToken.serialize(), tokenFactory.ttl());
                });
    }

    private static boolean isInvalidCredentials(Throwable failure) {
        return failure instanceof KeyMasterException exception
                && exception.getCode() == ErrorCode.INVALID_CREDENTIALS;
    }

    private static boolean hasAcceptablePassword(char[] password) {
        if (password == null || password.length == 0) {
            return false;
        }

        char[] copy = password.clone();
        char[] normalized = Secrets.normalize(copy);

        try {
            return normalized.length > 0 && normalized.length <= MAX_PASSWORD_LENGTH;
        } finally {
            Secrets.wipe(normalized);
        }
    }

    private static long retryAfterSeconds(TooManyRequestsException exception) {
        Duration retryAfter = exception.getRetryAfter();
        if (retryAfter == null || retryAfter.isZero() || retryAfter.isNegative()) {
            return 1;
        }
        return Math.max(1, (retryAfter.toMillis() + 999) / 1000);
    }
}
