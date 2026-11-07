package ru.zeker.keymaster.domain.context;

import java.util.UUID;

public record Actor(UUID userId, String requestId) {
}