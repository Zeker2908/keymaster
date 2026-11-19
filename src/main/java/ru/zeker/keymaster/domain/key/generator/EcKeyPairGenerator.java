package ru.zeker.keymaster.domain.key.generator;

import ru.zeker.keymaster.domain.key.GeneratedKey;
import ru.zeker.keymaster.domain.key.codec.EcKeyCodec;
import ru.zeker.keymaster.util.Secrets;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

public class EcKeyPairGenerator implements KeyPairGeneratorStrategy {

    private static final String ALGORITHM = "EC";

    private final String curve;

    public EcKeyPairGenerator(String curve) {
        this.curve = curve;
    }

    @Override
    public GeneratedKey generate() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
        generator.initialize(new ECGenParameterSpec(curve));

        KeyPair keyPair = generator.generateKeyPair();

        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();

        String kid = EcKeyCodec.thumbprint(publicKey);

        byte[] publicSpki = EcKeyCodec.toSpki(publicKey);
        byte[] privatePkcs8 = EcKeyCodec.toPkcs8(keyPair.getPrivate());

        try {
            return new GeneratedKey(kid, publicSpki, privatePkcs8);
        } finally {
            Secrets.wipe(privatePkcs8);
        }
    }
}
