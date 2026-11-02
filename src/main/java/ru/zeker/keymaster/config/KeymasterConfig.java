package ru.zeker.keymaster.config;

import io.smallrye.config.ConfigMapping;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;

import java.util.Optional;

@ConfigMapping(prefix = "keymaster")
public interface KeymasterConfig {

    @NotBlank
    String issuer();

    @NotBlank
    String audience();

    @Valid
    Password password();

    @Valid
    Bootstrap bootstrap();

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

    interface Bootstrap {
        @Valid
        Admin admin();

        interface Admin {
            boolean enabled();

            Optional<String> login();

            Optional<String> password();
        }
    }
}
