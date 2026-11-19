package ru.zeker.keymaster.config;

import io.smallrye.config.ConfigMapping;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import ru.zeker.keymaster.domain.Algorithm;

import java.util.Optional;

@ConfigMapping(prefix = "keymaster.bootstrap")
public interface BootstrapConfig {

    @Valid
    Admin admin();

    @Valid
    SigningKey signingKey();

    interface Admin {
        boolean enabled();

        Optional<String> login();

        Optional<String> password();
    }

    interface SigningKey {
        boolean enabled();

        @NotNull
        Algorithm algorithm();
    }
}
