package ru.zeker.keymaster.config;

import io.smallrye.config.ConfigMapping;
import jakarta.validation.constraints.NotBlank;

@ConfigMapping(prefix = "keymaster")
public interface JwtConfig {

    @NotBlank
    String issuer();

    @NotBlank
    String audience();
}
