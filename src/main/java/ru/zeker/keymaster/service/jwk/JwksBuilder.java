package ru.zeker.keymaster.service.jwk;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import lombok.extern.slf4j.Slf4j;
import ru.zeker.keymaster.domain.Algorithm;
import ru.zeker.keymaster.domain.key.KeyHeader;
import ru.zeker.keymaster.exception.ErrorCode;
import ru.zeker.keymaster.exception.KeyMasterException;
import ru.zeker.keymaster.mapper.jwk.JwkMapper;
import ru.zeker.keymaster.service.key.SigningKeyService;

import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

@Slf4j
@ApplicationScoped
public class JwksBuilder {

    private static final int MAX_KEYS = 50;

    private final Map<Algorithm, JwkMapper> jwkMapperMap;
    private final SigningKeyService signingKeys;

    public JwksBuilder(
            Instance<JwkMapper> mappers,
            SigningKeyService signingKeys
    ) {
        this.jwkMapperMap = mappers.stream()
                .collect(Collectors.toUnmodifiableMap(
                        JwkMapper::supports,
                        Function.identity()
                ));
        this.signingKeys = signingKeys;
    }

    public Uni<JWKSet> getJwks() {
        return signingKeys.listPublished()
                .map(keys -> {
                    validateKeysCount(keys.size());
                    return new JWKSet(
                            keys.stream()
                                    .map(this::mapToJwk)
                                    .toList()
                    );
                });
    }

    private void validateKeysCount(int count) {
        if (count == 0) {
            log.error("JWKS generation failed: no published signing keys");
            throw new KeyMasterException(ErrorCode.JWK_UNAVAILABLE, "No published signing keys");
        }

        if (count > MAX_KEYS) {
            log.error("JWKS generation failed: published keys count {} exceeds maximum {}", count, MAX_KEYS);
            throw new KeyMasterException(ErrorCode.JWK_UNAVAILABLE, "Too many published signing keys");
        }
    }

    private JWK mapToJwk(KeyHeader key) {
        return getMapper(key.alg()).toJwk(key);
    }

    private JwkMapper getMapper(Algorithm algorithm) {
        return Optional.ofNullable(jwkMapperMap.get(algorithm))
                .orElseThrow(() -> new IllegalStateException("No JWK mapper for algorithm: " + algorithm));
    }
}
