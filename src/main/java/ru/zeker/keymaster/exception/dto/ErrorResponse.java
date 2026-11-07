package ru.zeker.keymaster.exception.dto;

import java.time.Instant;
import java.util.List;

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