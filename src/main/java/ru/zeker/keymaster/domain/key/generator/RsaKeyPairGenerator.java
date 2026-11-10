package ru.zeker.keymaster.domain.key.generator;

import ru.zeker.keymaster.domain.key.GeneratedKey;
import ru.zeker.keymaster.domain.key.codec.RsaKeyCodec;
import ru.zeker.keymaster.util.Secrets;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;

public class RsaKeyPairGenerator implements KeyPairGeneratorStrategy {

    private static final String ALGORITHM = "RSA";

    private final int keySize;

    public RsaKeyPairGenerator(int keySize) {
        this.keySize = keySize;
    }

    @Override
    public GeneratedKey generate() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
        generator.initialize(keySize);

        KeyPair keyPair = generator.generateKeyPair();

        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        String kid = RsaKeyCodec.thumbprint(publicKey);

        byte[] publicSpki = RsaKeyCodec.toSpki(publicKey);
        byte[] privatePkcs8 = RsaKeyCodec.toPkcs8(keyPair.getPrivate());

        try {
            return new GeneratedKey(kid, publicSpki, privatePkcs8);
        } finally {
            Secrets.wipe(privatePkcs8);
        }
    }
}
