package ru.zeker.keymaster.dto.response;

import com.fasterxml.jackson.annotation.JsonFormat;
import io.quarkus.runtime.annotations.RegisterForReflection;
import ru.zeker.keymaster.domain.Patterns;

import java.time.Instant;
import java.util.UUID;

@RegisterForReflection
public record RoleDetailsResponse(
        UUID id,
        String name,
        String description,
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = Patterns.TIME_FORMAT, timezone = "UTC")
        Instant createdAt
) {
}
