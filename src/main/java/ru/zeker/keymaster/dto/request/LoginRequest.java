package ru.zeker.keymaster.dto.request;

import io.quarkus.runtime.annotations.RegisterForReflection;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;

@RegisterForReflection
public record LoginRequest(
        @NotBlank
        String login,

        @NotEmpty
        char[] password
) {
}
