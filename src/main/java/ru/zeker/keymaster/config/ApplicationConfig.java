package ru.zeker.keymaster.config;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Disposes;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import ru.zeker.keymaster.domain.key.KeyLifecycle;

import java.time.Clock;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

@ApplicationScoped
public class ApplicationConfig {

    @Produces
    @ApplicationScoped
    Clock clock() {
        return Clock.systemUTC();
    }

    @Produces
    @Singleton
    Argon2 argon2() {
        return Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
    }

    @Produces
    @Singleton
    KeyLifecycle keyLifecycle(KeymasterConfig config) {
        var conf = config.keys();
        return new KeyLifecycle(conf.jwksPollInterval(), conf.leeway(), conf.maxAccessTtl());
    }

    @Produces
    @Singleton
    @Named("password-hashing")
    ExecutorService passwordHashingExecutor(KeymasterConfig config) {
        var conf = config.password().argon2();
        ThreadFactory threadFactory = Thread.ofPlatform()
                .name("password-hashing-", 1)
                .factory();
        return new ThreadPoolExecutor(
                conf.maxConcurrentHashes(),
                conf.maxConcurrentHashes(),
                0L,
                TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(conf.maxQueue()),
                threadFactory,
                new ThreadPoolExecutor.AbortPolicy()
        );
    }

    @Produces
    @Singleton
    @Named("key-generation")
    public ExecutorService keyGenerationExecutor() {
        ThreadFactory threadFactory = Thread.ofPlatform()
                .name("key-generation-", 1)
                .factory();

        return new ThreadPoolExecutor(
                1,
                1,
                0L,
                TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(4),
                threadFactory,
                new ThreadPoolExecutor.AbortPolicy()
        );
    }

    void disposePasswordHashingExecutor(@Disposes @Named("password-hashing") ExecutorService executor) {
        shutdownExecutor(executor);
    }

    void disposeKeyGenerationExecutor(@Disposes @Named("key-generation") ExecutorService executor) {
        shutdownExecutor(executor);
    }

    private void shutdownExecutor(ExecutorService executor) {
        executor.shutdown();

        try {
            if (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
