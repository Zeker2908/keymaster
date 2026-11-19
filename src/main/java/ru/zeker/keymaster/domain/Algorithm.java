package ru.zeker.keymaster.domain;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import ru.zeker.keymaster.domain.key.codec.EcKeyCodec;
import ru.zeker.keymaster.domain.key.codec.RsaKeyCodec;
import ru.zeker.keymaster.domain.key.generator.EcKeyPairGenerator;
import ru.zeker.keymaster.domain.key.generator.KeyPairGeneratorStrategy;
import ru.zeker.keymaster.domain.key.generator.RsaKeyPairGenerator;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.util.function.Function;

@Getter
@RequiredArgsConstructor
public enum Algorithm {

    RS256(
            JWSAlgorithm.RS256,
            RsaKeyCodec::privateFromPkcs8,
            RsaKeyCodec::publicFromSpki,
            new RsaKeyPairGenerator(2048)
    ),
    RS384(
            JWSAlgorithm.RS384,
            RsaKeyCodec::privateFromPkcs8,
            RsaKeyCodec::publicFromSpki,
            new RsaKeyPairGenerator(2048)
    ),
    RS512(
            JWSAlgorithm.RS512,
            RsaKeyCodec::privateFromPkcs8,
            RsaKeyCodec::publicFromSpki,
            new RsaKeyPairGenerator(2048)
    ),
    PS256(
            JWSAlgorithm.PS256,
            RsaKeyCodec::privateFromPkcs8,
            RsaKeyCodec::publicFromSpki,
            new RsaKeyPairGenerator(2048)
    ),
    PS384(
            JWSAlgorithm.PS384,
            RsaKeyCodec::privateFromPkcs8,
            RsaKeyCodec::publicFromSpki,
            new RsaKeyPairGenerator(2048)
    ),
    PS512(
            JWSAlgorithm.PS512,
            RsaKeyCodec::privateFromPkcs8,
            RsaKeyCodec::publicFromSpki,
            new RsaKeyPairGenerator(2048)
    ),

    ES256(
            JWSAlgorithm.ES256,
            EcKeyCodec::privateFromPkcs8,
            EcKeyCodec::publicFromSpki,
            new EcKeyPairGenerator("secp256r1")
    ),
    ES384(
            JWSAlgorithm.ES384,
            EcKeyCodec::privateFromPkcs8,
            EcKeyCodec::publicFromSpki,
            new EcKeyPairGenerator("secp384r1")
    ),
    ES512(
            JWSAlgorithm.ES512,
            EcKeyCodec::privateFromPkcs8,
            EcKeyCodec::publicFromSpki,
            new EcKeyPairGenerator("secp521r1")
    );

    private final JWSAlgorithm jwsAlgorithm;
    private final Function<byte[], PrivateKey> privateKeyDecoder;
    private final Function<byte[], PublicKey> publicKeyDecoder;
    private final KeyPairGeneratorStrategy generator;

    public JWSSigner createSigner(PrivateKey key) throws JOSEException {
        return switch (this) {
            case RS256, RS384, RS512, PS256, PS384, PS512 -> new RSASSASigner(key);
            case ES256, ES384, ES512 -> new ECDSASigner((ECPrivateKey) key);
        };
    }
}

