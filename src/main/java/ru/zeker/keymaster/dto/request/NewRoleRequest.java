package ru.zeker.keymaster.dto.request;

import io.quarkus.runtime.annotations.RegisterForReflection;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import ru.zeker.keymaster.domain.Patterns;

@RegisterForReflection
public record NewRoleRequest(
        @NotBlank @Pattern(regexp = Patterns.ROLE_NAME)
        String name,

        @NotBlank
        @Size(max = 1024)
        String description
) {
}
