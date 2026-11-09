package ru.zeker.keymaster.exception.dto;

import io.quarkus.runtime.annotations.RegisterForReflection;

@RegisterForReflection
public record ErrorDetail(
        String field,
        String message
) {
}
