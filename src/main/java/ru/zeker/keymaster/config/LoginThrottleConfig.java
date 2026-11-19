package ru.zeker.keymaster.config;

import io.smallrye.config.ConfigMapping;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

import java.time.Duration;

@ConfigMapping(prefix = "keymaster.auth.login")
public interface LoginThrottleConfig {

    @Valid
    IpLimit ipLimit();

    @Valid
    LoginLimit loginLimit();

    @Valid
    PairLimit pairLimit();

    interface IpLimit {
        boolean enabled();

        @Positive
        int maxAttempts();

        @NotNull
        Duration window();
    }

    interface LoginLimit {
        @Positive
        int maxAttempts();

        @NotNull
        Duration window();
    }

    interface PairLimit {
        @Positive
        int maxAttempts();

        @NotNull
        Duration window();
    }
}
