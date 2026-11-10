package ru.zeker.keymaster.mapper.jwk;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.util.Base64URL;
import ru.zeker.keymaster.domain.key.KeyHeader;
import ru.zeker.keymaster.domain.key.codec.EcKeyCodec;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;

public abstract class EcJwkMapper implements JwkMapper {

    protected abstract Curve curve();

    @Override
    public ECKey toJwk(KeyHeader key) {
        PublicKey publicKey = supports().getPublicKeyDecoder().apply(key.publicKey());
        ECPublicKey ecPublicKey = (ECPublicKey) publicKey;

        return new ECKey.Builder(
                curve(),
                new Base64URL(EcKeyCodec.jwkX(ecPublicKey)),
                new Base64URL(EcKeyCodec.jwkY(ecPublicKey))
        )
                .keyID(key.kid())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.parse(supports().name()))
                .build();
    }
}
