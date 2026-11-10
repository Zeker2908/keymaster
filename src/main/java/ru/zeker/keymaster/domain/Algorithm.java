package ru.zeker.keymaster.domain;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import ru.zeker.keymaster.domain.key.codec.RsaKeyCodec;
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
            new RsaKeyPairGenerator()
    );

    private final Function<byte[], PrivateKey> privateKeyDecoder;
    private final Function<byte[], PublicKey> publicKeyDecoder;
    private final KeyPairGeneratorStrategy generator;
}
