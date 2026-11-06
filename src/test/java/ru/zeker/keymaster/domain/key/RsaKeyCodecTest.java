package ru.zeker.keymaster.domain.key;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RsaKeyCodecTest {

    private static final int KEY_BITS = 2048;
    private static final int MODULUS_BYTES = KEY_BITS / 8;
    private static final int GENERATED_KEYS = 50;

    private static final Pattern KID_CHECK = Pattern.compile("^[A-Za-z0-9_-]{43}$");

    /**
     * RFC 7638, section 3.1.
     */
    private static final String RFC_7638_N =
            "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt"
                    + "VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6"
                    + "4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD"
                    + "W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9"
                    + "1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH"
                    + "aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

    private static final String RFC_7638_E = "AQAB";

    private static final String RFC_7638_THUMBPRINT =
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

    @Test
    void generatedModulusIsExactly256UnsignedBytesForFiftyKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(KEY_BITS);

        for (int i = 0; i < GENERATED_KEYS; i++) {
            RSAPublicKey publicKey = (RSAPublicKey) generator.generateKeyPair().getPublic();
            int keyNumber = i + 1;

            byte[] modulus = Base64.getUrlDecoder().decode(RsaKeyCodec.jwkN(publicKey));

            assertEquals(MODULUS_BYTES, modulus.length,
                    () -> "modulus length for generated key #" + keyNumber);
            assertNotEquals(0, modulus[0],
                    () -> "leading zero in modulus of generated key #" + keyNumber);
            assertNotEquals(0, publicKey.getModulus().signum());
            assertEquals(RFC_7638_E, RsaKeyCodec.jwkE(publicKey),
                    () -> "public exponent for generated key #" + keyNumber);

            String kid = RsaKeyCodec.thumbprint(publicKey);
            assertTrue(KID_CHECK.matcher(kid).matches(),
                    () -> "kid does not pass signing_key_kid_chk: " + kid);
        }
    }

    @Test
    void thumbprintMatchesRfc7638ReferenceAndNimbus() throws Exception {
        BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(RFC_7638_N));
        BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(RFC_7638_E));

        RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
                .generatePublic(new RSAPublicKeySpec(modulus, exponent));

        assertEquals(RFC_7638_N, RsaKeyCodec.jwkN(publicKey));
        assertEquals(RFC_7638_E, RsaKeyCodec.jwkE(publicKey));
        assertEquals(RFC_7638_THUMBPRINT, RsaKeyCodec.thumbprint(publicKey));

        RSAKey nimbusKey = new RSAKey.Builder(
                new Base64URL(RFC_7638_N),
                new Base64URL(RFC_7638_E)
        ).build();

        assertEquals(nimbusKey.computeThumbprint().toString(),
                RsaKeyCodec.thumbprint(publicKey));
    }

    @Test
    void thumbprintPassesKidCheck() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        String kid = RsaKeyCodec.thumbprint((RSAPublicKey) keyPair.getPublic());

        assertEquals(43, kid.length());
        assertTrue(KID_CHECK.matcher(kid).matches(),
                () -> "kid does not pass signing_key_kid_chk: " + kid);
    }

    @Test
    void sha256WithRsaSignatureRoundTripsThroughPkcs8AndSpki() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(KEY_BITS);
        KeyPair keyPair = generator.generateKeyPair();
        byte[] data = "payload to sign".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        var privateKey = RsaKeyCodec.privateFromPkcs8(
                RsaKeyCodec.toPkcs8(keyPair.getPrivate()));
        var publicKey = RsaKeyCodec.publicFromSpki(
                RsaKeyCodec.toSpki(keyPair.getPublic()));

        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(data);
        byte[] signature = signer.sign();

        assertEquals(MODULUS_BYTES, signature.length);

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(data);
        assertTrue(verifier.verify(signature));

        verifier.update((byte) 0x01);
        assertFalse(verifier.verify(signature));
    }
}
