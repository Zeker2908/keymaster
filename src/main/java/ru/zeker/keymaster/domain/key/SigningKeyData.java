package ru.zeker.keymaster.domain.key;

import io.quarkus.runtime.annotations.RegisterForReflection;
import ru.zeker.keymaster.domain.Algorithm;

import java.security.PrivateKey;

@RegisterForReflection
public record SigningKeyData(
        String kid,
        Algorithm algorithm,
        PrivateKey privateKey
) {
}
