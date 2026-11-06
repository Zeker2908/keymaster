package ru.zeker.keymaster.domain.key;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;

import java.time.Instant;
import java.util.Objects;

@Embeddable
public record KeyTimeline(
        @Column(name = "publish_at", nullable = false) Instant publishAt,
        @Column(name = "activate_at", nullable = false) Instant activateAt,
        @Column(name = "retire_at") Instant retireAt,
        @Column(name = "remove_at") Instant removeAt,
        @Column(name = "revoked_at") Instant revokedAt
) {
    public KeyTimeline {
        Objects.requireNonNull(publishAt, "publishAt must not be null");
        Objects.requireNonNull(activateAt, "activateAt must not be null");

        if (publishAt.isAfter(activateAt)) {
            throw new IllegalArgumentException("publishAt must not be after activateAt");
        }
        if (retireAt != null && activateAt.isAfter(retireAt)) {
            throw new IllegalArgumentException("activateAt must not be after retireAt");
        }
        if (removeAt != null && retireAt == null) {
            throw new IllegalArgumentException("retireAt must be set when removeAt is set");
        }
        if (removeAt != null && retireAt.isAfter(removeAt)) {
            throw new IllegalArgumentException("retireAt must not be after removeAt");
        }
    }
}