package ru.zeker.keymaster.dto.request;

import io.quarkus.runtime.annotations.RegisterForReflection;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.List;

@RegisterForReflection
public record NewClientRequest(

        @NotBlank
        @Size(min = 3, max = 32)
        @Pattern(regexp = "^[a-z0-9._-]+$")
        String name,

        List<@NotBlank @Pattern(regexp = "^[a-z0-9][a-z0-9._:-]{0,63}$") String> roles
) {
}
