package ru.zeker.keymaster.dto.request;

import io.quarkus.runtime.annotations.RegisterForReflection;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@RegisterForReflection
public record LoginRequest(
        @NotBlank
        @Size(max = 32)
        String login,

        char[] password
) {
}
