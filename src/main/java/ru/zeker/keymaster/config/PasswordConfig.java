package ru.zeker.keymaster.config;

import io.smallrye.config.ConfigMapping;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Positive;

@ConfigMapping(prefix = "keymaster.password")
public interface PasswordConfig {

    @Valid
    Argon2 argon2();

    interface Argon2 {
        @Positive
        int iterations();

        @Positive
        int memory();

        @Positive
        int parallelism();

        @Positive
        int maxConcurrentHashes();

        @Positive
        int maxQueue();
    }
}
