package ru.zeker.keymaster.service;

import com.nimbusds.jwt.JWT;
import io.quarkus.runtime.StartupEvent;
import io.quarkus.vertx.VertxContextSupport;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import lombok.extern.slf4j.Slf4j;
import ru.zeker.keymaster.domain.jwt.Subject;
import ru.zeker.keymaster.dto.request.LoginRequest;
import ru.zeker.keymaster.dto.response.TokenResponse;
import ru.zeker.keymaster.exception.ErrorCode;
import ru.zeker.keymaster.exception.KeyMasterException;
import ru.zeker.keymaster.service.jwt.AccessTokenFactory;
import ru.zeker.keymaster.service.key.ActiveKeyResolver;
import ru.zeker.keymaster.service.password.PasswordHasher;

import java.time.Clock;
import java.time.Duration;
import java.util.UUID;

@Slf4j
@ApplicationScoped
public class AuthService {

    private final ActiveKeyResolver resolver;
    private final AccessTokenFactory tokenFactory;
    private final PrincipalService principals;
    private final PasswordHasher hasher;
    private final Clock clock;

    private String dummyHash;

    public AuthService(
            ActiveKeyResolver resolver,
            AccessTokenFactory tokenFactory,
            PrincipalService principals,
            PasswordHasher hasher,
            Clock clock) {
        this.resolver = resolver;
        this.tokenFactory = tokenFactory;
        this.principals = principals;
        this.hasher = hasher;
        this.clock = clock;
    }

    void onStart(@Observes StartupEvent e) throws Throwable {
        dummyHash = VertxContextSupport.subscribeAndAwait(
                () -> hasher.hash(UUID.randomUUID().toString().toCharArray()).ifNoItem()
                        .after(Duration.ofSeconds(30))
                        .fail()
        );
    }

    /**
     * Аутентификация по логину и паролю.
     *
     * <p>Пользователи с {@code kind != USER} и {@code status != ACTIVE} не попадают
     * в выборку и проходят тот же путь, что и несуществующий логин: проверка пароля
     * по фиктивному хэшу. Это выравнивает время ответа и не даёт отличить
     * отключённую учётную запись или клиента от неверного пароля.</p>
     *
     */
    public Uni<TokenResponse> login(LoginRequest request) {
        return principals.getByLogin(request.login())
                .chain(subject -> {
                    String hash = subject != null ? subject.secretHash() : dummyHash;
                    return hasher.verify(hash, request.password())
                            .chain(valid -> {
                                if (subject == null || !valid) {
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
}
