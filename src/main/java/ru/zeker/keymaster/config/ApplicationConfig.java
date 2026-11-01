package ru.zeker.keymaster.config;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Disposes;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Named;
import jakarta.inject.Singleton;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

@Singleton
public class ApplicationConfig {

    @Produces
    @ApplicationScoped
    Argon2 argon2() {
        return Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
    }

    @Produces
    @ApplicationScoped
    @Named("password-hashing")
    ExecutorService passwordHashingExecutor(KeymasterConfig config) {
        var conf = config.password().argon2();
        return new ThreadPoolExecutor(
                conf.maxConcurrentHashes(),
                conf.maxConcurrentHashes(),
                0L,
                TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(conf.maxQueue()),
                new ThreadPoolExecutor.AbortPolicy()
        );
    }

    void shutdown(@Disposes @Named("password-hashing") ExecutorService executor) {
        executor.shutdown();
    }
}