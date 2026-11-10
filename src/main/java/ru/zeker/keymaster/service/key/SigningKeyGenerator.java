package ru.zeker.keymaster.service.key;

import io.smallrye.mutiny.Uni;
import io.vertx.core.Context;
import io.vertx.core.Vertx;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Named;
import ru.zeker.keymaster.domain.Algorithm;
import ru.zeker.keymaster.domain.key.GeneratedKey;
import ru.zeker.keymaster.exception.ServiceOverloadedException;

import java.security.GeneralSecurityException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;

@ApplicationScoped
public final class SigningKeyGenerator {

    private final ExecutorService executor;

    public SigningKeyGenerator(@Named("key-generation") ExecutorService executor) {
        this.executor = executor;
    }

    public Uni<GeneratedKey> generate(Algorithm algorithm) {
        Context context = Vertx.currentContext();

        return Uni.createFrom()
                .item(() -> generateKey(algorithm))
                .runSubscriptionOn(executor)
                .onFailure(RejectedExecutionException.class)
                .transform(ServiceOverloadedException::new)
                .emitOn(context == null
                        ? Runnable::run
                        : command -> context.runOnContext(_ -> command.run())
                );
    }

    private GeneratedKey generateKey(Algorithm algorithm) {
        try {
            return algorithm.getGenerator().generate();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("%s key generation failed".formatted(algorithm.name()), e);
        }
    }
}
