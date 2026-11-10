package ru.zeker.keymaster.domain;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import ru.zeker.keymaster.domain.key.codec.EcKeyCodec;
import ru.zeker.keymaster.domain.key.codec.RsaKeyCodec;
import ru.zeker.keymaster.domain.key.generator.EcKeyPairGenerator;
import ru.zeker.keymaster.domain.key.generator.KeyPairGeneratorStrategy;
import ru.zeker.keymaster.domain.key.generator.RsaKeyPairGenerator;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.function.Function;

@Getter
@RequiredArgsConstructor
public enum Algorithm {

    RS256(
            RsaKeyCodec::privateFromPkcs8,
            RsaKeyCodec::publicFromSpki,
            new RsaKeyPairGenerator(2048)
    ),
    RS384(
            RsaKeyCodec::privateFromPkcs8,
            RsaKeyCodec::publicFromSpki,
            new RsaKeyPairGenerator(2048)
    ),
    RS512(
            RsaKeyCodec::privateFromPkcs8,
            RsaKeyCodec::publicFromSpki,
            new RsaKeyPairGenerator(2048)
    ),
    PS256(
            RsaKeyCodec::privateFromPkcs8,
            RsaKeyCodec::publicFromSpki,
            new RsaKeyPairGenerator(2048)
    ),
    PS384(
            RsaKeyCodec::privateFromPkcs8,
            RsaKeyCodec::publicFromSpki,
            new RsaKeyPairGenerator(2048)
    ),
    PS512(
            RsaKeyCodec::privateFromPkcs8,
            RsaKeyCodec::publicFromSpki,
            new RsaKeyPairGenerator(2048)
    ),

    ES256(
            EcKeyCodec::privateFromPkcs8,
            EcKeyCodec::publicFromSpki,
            new EcKeyPairGenerator("secp256r1")
    ),
    ES384(
            EcKeyCodec::privateFromPkcs8,
            EcKeyCodec::publicFromSpki,
            new EcKeyPairGenerator("secp384r1")
    ),
    ES512(
            EcKeyCodec::privateFromPkcs8,
            EcKeyCodec::publicFromSpki,
            new EcKeyPairGenerator("secp521r1")
    );

    private final Function<byte[], PrivateKey> privateKeyDecoder;
    private final Function<byte[], PublicKey> publicKeyDecoder;
    private final KeyPairGeneratorStrategy generator;
}
