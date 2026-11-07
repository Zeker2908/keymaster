package ru.zeker.keymaster.exception.dto;

public record ErrorDetail(
        String field,
        String message
) {
}