package ru.zeker.keymaster.dto.request;

import io.quarkus.runtime.annotations.RegisterForReflection;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import ru.zeker.keymaster.domain.Patterns;

import java.util.List;

@RegisterForReflection
public record NewClientRequest(

        @NotBlank
        @Size(min = 3, max = 32)
        @Pattern(regexp = Patterns.LOGIN)
        String name,

        List<@NotBlank @Pattern(regexp = Patterns.ROLE_NAME) String> roles
) {
}
