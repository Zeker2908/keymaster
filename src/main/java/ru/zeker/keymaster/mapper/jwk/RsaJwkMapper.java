package ru.zeker.keymaster.mapper.jwk;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import jakarta.enterprise.context.ApplicationScoped;
import ru.zeker.keymaster.domain.Algorithm;
import ru.zeker.keymaster.domain.key.KeyHeader;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

@ApplicationScoped
public class RsaJwkMapper implements JwkMapper {

    @Override
    public Algorithm supports() {
        return Algorithm.RS256;
    }

    @Override
    public RSAKey toJwk(KeyHeader key) {
        PublicKey publicKey = supports().getPublicKeyDecoder().apply(key.publicKey());

        return new RSAKey.Builder((RSAPublicKey) publicKey)
                .keyID(key.kid())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .build();
    }
}
