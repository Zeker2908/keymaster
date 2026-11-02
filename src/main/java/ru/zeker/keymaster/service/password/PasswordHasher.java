package ru.zeker.keymaster.service.password;

import de.mkammerer.argon2.Argon2;
import io.smallrye.mutiny.Uni;
import io.vertx.core.Context;
import io.vertx.core.Vertx;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Named;
import lombok.extern.slf4j.Slf4j;
import ru.zeker.keymaster.config.KeymasterConfig;
import ru.zeker.keymaster.exception.ServiceOverloadedException;
import ru.zeker.keymaster.util.PasswordUtils;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.function.Supplier;

@Slf4j
@ApplicationScoped
public class PasswordHasher {

    private final Argon2 argon2;
    private final KeymasterConfig.Password.Argon2 config;
    private final ExecutorService executor;

    public PasswordHasher(Argon2 argon2,
                          KeymasterConfig config,
                          @Named("password-hashing") ExecutorService executor) {
        this.argon2 = argon2;
        this.config = config.password().argon2();
        this.executor = executor;
    }

    public Uni<String> hash(char[] password) {
        char[] normalized = PasswordUtils.normalize(password);
        return execute("hash", normalized, () -> argon2.hash(
                config.iterations(),
                config.memory(),
                config.parallelism(),
                normalized,
                StandardCharsets.UTF_8));
    }

    public Uni<Boolean> verify(String hashPassword, char[] password) {
        char[] normalized = PasswordUtils.normalize(password);
        return execute("verify", normalized, () -> argon2.verify(hashPassword, normalized));
    }

    private <T> Uni<T> execute(String operationName, char[] password, Supplier<T> operation) {
        Context context = Vertx.currentContext();

        Uni<T> uni = Uni.createFrom().item(() -> {
                    long start = System.nanoTime();
                    try {
                        return operation.get();
                    } finally {
                        long durationMs = (System.nanoTime() - start) / 1_000_000;
                        log.debug("Password {} completed in {} ms", operationName, durationMs);
                        PasswordUtils.wipe(password);
                    }
                }).runSubscriptionOn(executor)
                .onFailure(RejectedExecutionException.class)
                .invoke(() -> PasswordUtils.wipe(password))
                .onFailure(RejectedExecutionException.class)
                .transform(ServiceOverloadedException::new);

        return context == null
                ? uni
                : uni.emitOn(runnable -> context.runOnContext(_ -> runnable.run()));
    }
}
