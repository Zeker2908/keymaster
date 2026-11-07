package ru.zeker.keymaster.domain.key;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public final class RsaKeyCodec {

    private static final String ALGORITHM = "RSA";
    private static final String SHA_256 = "SHA-256";

    private static final Base64.Encoder BASE64_URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    private static final String E_S_KTY_RSA_N_S = "{\"e\":\"%s\",\"kty\":\"RSA\",\"n\":\"%s\"}";

    private RsaKeyCodec() {
    }

    public static byte[] toSpki(PublicKey publicKey) {
        return publicKey.getEncoded();
    }

    public static PublicKey publicFromSpki(byte[] encoded) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);

            return keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Invalid RSA public key", e);
        }
    }

    public static byte[] toPkcs8(PrivateKey privateKey) {
        return privateKey.getEncoded();
    }

    public static PrivateKey privateFromPkcs8(byte[] encoded) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);

            return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Invalid RSA private key", e);
        }
    }

    public static String jwkN(RSAPublicKey publicKey) {
        return encodeUnsigned(publicKey.getModulus());
    }

    public static String jwkE(RSAPublicKey publicKey) {
        return encodeUnsigned(publicKey.getPublicExponent());
    }

    public static String thumbprint(RSAPublicKey publicKey) {
        String json = E_S_KTY_RSA_N_S.formatted(jwkE(publicKey), jwkN(publicKey));

        try {
            MessageDigest digest = MessageDigest.getInstance(SHA_256);

            return BASE64_URL_ENCODER.encodeToString(digest.digest(json.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    private static String encodeUnsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();

        if (bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }

        return BASE64_URL_ENCODER.encodeToString(bytes);
    }
}
