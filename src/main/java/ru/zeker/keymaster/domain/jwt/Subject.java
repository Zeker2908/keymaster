package ru.zeker.keymaster.domain.jwt;

import io.quarkus.runtime.annotations.RegisterForReflection;
import lombok.ToString;

import java.util.List;
import java.util.UUID;

@RegisterForReflection
public record Subject(
        UUID userId,
        String secretHash,
        List<String> roles
) {
    @Override
    public String toString() {
        return "Subject[userId=" + userId + ", roles=" + roles + "]";
    }
}
