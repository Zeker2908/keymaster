package ru.zeker.keymaster.dto.response;

import com.fasterxml.jackson.annotation.JsonFormat;
import io.quarkus.runtime.annotations.RegisterForReflection;
import ru.zeker.keymaster.domain.Patterns;
import ru.zeker.keymaster.domain.PrincipalKind;
import ru.zeker.keymaster.domain.PrincipalStatus;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@RegisterForReflection
public record UserResponse(
        UUID id,
        String login,
        PrincipalKind kind,
        PrincipalStatus status,
        List<RoleResponse> roles,
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = Patterns.TIME_FORMAT, timezone = "UTC")
        Instant createdAt
) {
    public UserResponse {
        roles = roles == null ? List.of() : List.copyOf(roles);
    }
}
