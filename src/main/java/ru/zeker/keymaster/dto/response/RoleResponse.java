package ru.zeker.keymaster.dto.response;

import io.quarkus.runtime.annotations.RegisterForReflection;

@RegisterForReflection
public record RoleResponse(
        String name
) {
}
