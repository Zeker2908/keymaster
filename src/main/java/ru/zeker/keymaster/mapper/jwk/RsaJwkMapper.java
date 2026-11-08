package ru.zeker.keymaster.mapper.jwk;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import jakarta.enterprise.context.ApplicationScoped;
import ru.zeker.keymaster.domain.Algorithm;
import ru.zeker.keymaster.domain.key.KeyHeader;
import ru.zeker.keymaster.domain.key.RsaKeyCodec;

import java.security.interfaces.RSAPublicKey;

@ApplicationScoped
public class RsaJwkMapper implements JwkMapper {

    @Override
    public Algorithm supports() {
        return Algorithm.RS256;
    }

    @Override
    public RSAKey toJwk(KeyHeader key) {
        RSAPublicKey publicKey = RsaKeyCodec.publicFromSpki(key.publicKey());

        return new RSAKey.Builder(publicKey)
                .keyID(key.kid())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.parse(key.alg().name()))
                .build();
    }
}
