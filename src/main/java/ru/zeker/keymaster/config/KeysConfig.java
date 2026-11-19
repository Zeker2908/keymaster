package ru.zeker.keymaster.config;

import io.smallrye.config.ConfigMapping;
import jakarta.validation.constraints.NotBlank;
import ru.zeker.keymaster.config.validation.ValidMasterKey;

import java.time.Duration;

@ConfigMapping(prefix = "keymaster.keys")
public interface KeysConfig {

    Duration jwksPollInterval();

    Duration leeway();

    Duration maxAccessTtl();

    @NotBlank
    @ValidMasterKey
    String masterKey();
}
