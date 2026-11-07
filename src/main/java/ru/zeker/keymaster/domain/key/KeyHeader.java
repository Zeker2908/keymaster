package ru.zeker.keymaster.domain.key;

import ru.zeker.keymaster.domain.Algorithm;

public record KeyHeader (
        String kid,
        Algorithm alg,
        byte[] publicKey,
        KeyTimeline timeline
) {
}
