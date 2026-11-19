package ru.zeker.keymaster.domain.context;

import io.quarkus.runtime.annotations.RegisterForReflection;

import java.util.UUID;

@RegisterForReflection
public record Actor(
        UUID userId,
        String requestId,
        String clientIp) {

    public static final Actor SYSTEM = new Actor(null, "bootstrap", null);
}
