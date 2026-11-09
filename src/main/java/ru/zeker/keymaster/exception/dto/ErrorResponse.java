package ru.zeker.keymaster.exception.dto;

import io.quarkus.runtime.annotations.RegisterForReflection;

import java.time.Instant;
import java.util.List;

@RegisterForReflection
public record ErrorResponse(
        Instant timestamp,
        int status,
        String error,
        String message,
        String path,
        List<ErrorDetail> details,
        String requestId
) {
    public ErrorResponse {
        details = details == null ? List.of() : List.copyOf(details);
    }
}
