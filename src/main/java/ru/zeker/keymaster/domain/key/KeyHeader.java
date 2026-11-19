package ru.zeker.keymaster.domain.key;

import io.quarkus.runtime.annotations.RegisterForReflection;
import ru.zeker.keymaster.domain.Algorithm;

import java.time.Instant;

@RegisterForReflection
public record KeyHeader(
        String kid,
        Algorithm alg,
        byte[] publicKey,
        Instant publishAt,
        Instant activateAt,
        Instant retireAt,
        Instant removeAt,
        Instant revokedAt
) {

    public KeyHeader(
            String kid,
            Algorithm alg,
            byte[] publicKey,
            KeyTimeline timeline
    ) {
        this(
                kid,
                alg,
                publicKey,
                timeline.publishAt(),
                timeline.activateAt(),
                timeline.retireAt(),
                timeline.removeAt(),
                timeline.revokedAt()
        );
    }

    public KeyTimeline timeline() {
        return new KeyTimeline(publishAt, activateAt, retireAt, removeAt, revokedAt);
    }
}
