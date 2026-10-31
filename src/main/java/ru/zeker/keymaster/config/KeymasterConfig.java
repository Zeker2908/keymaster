package ru.zeker.keymaster.config;

import io.smallrye.config.ConfigMapping;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;

@ConfigMapping(prefix = "keymaster")
public interface KeymasterConfig {
    @NotBlank
    String issuer();

    @NotBlank
    String audience();

    @Valid
    Password password();

    interface Password {
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
}
