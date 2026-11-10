
package ru.zeker.keymaster.domain.key.codec;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public final class EcKeyCodec {

    private static final String ALGORITHM = "EC";
    private static final String JWK_TEMPLATE = "{\"crv\":\"%s\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"}";

    private EcKeyCodec() {
    }

    public static byte[] toSpki(PublicKey publicKey) {
        return publicKey.getEncoded();
    }

    public static ECPublicKey publicFromSpki(byte[] encoded) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);

            return (ECPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Invalid ECDSA public key", e);
        }
    }

    public static byte[] toPkcs8(PrivateKey privateKey) {
        return privateKey.getEncoded();
    }

    public static ECPrivateKey privateFromPkcs8(byte[] encoded) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);

            return (ECPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Invalid ECDSA private key", e);
        }
    }

    public static String jwkX(ECPublicKey publicKey) {
        return encodeCoordinate(publicKey.getW().getAffineX(), coordinateSize(publicKey));
    }

    public static String jwkY(ECPublicKey publicKey) {
        return encodeCoordinate(publicKey.getW().getAffineY(), coordinateSize(publicKey));
    }

    public static String jwkCrv(ECPublicKey publicKey) {
        return switch (publicKey.getParams().getCurve().getField().getFieldSize()) {
            case 256 -> "P-256";
            case 384 -> "P-384";
            case 521 -> "P-521";
            default -> throw new IllegalArgumentException("Unsupported ECDSA curve");
        };
    }

    public static String thumbprint(ECPublicKey publicKey) {
        String json = JWK_TEMPLATE.formatted(
                jwkCrv(publicKey),
                jwkX(publicKey),
                jwkY(publicKey)
        );

        try {
            MessageDigest digest = MessageDigest.getInstance(Codecs.SHA_256);

            return Codecs.BASE64_URL_ENCODER.encodeToString(digest.digest(json.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    private static int coordinateSize(ECPublicKey publicKey) {
        if (!(publicKey.getParams().getCurve().getField() instanceof ECFieldFp)) {
            throw new IllegalArgumentException("Only prime field curves are supported");
        }

        return (publicKey.getParams().getCurve().getField().getFieldSize() + 7) / 8;
    }

    private static String encodeCoordinate(BigInteger value, int size) {
        byte[] bytes = value.toByteArray();

        if (bytes.length > size) {
            bytes = Arrays.copyOfRange(bytes, bytes.length - size, bytes.length);
        } else if (bytes.length < size) {
            byte[] padded = new byte[size];
            System.arraycopy(bytes, 0, padded, size - bytes.length, bytes.length);
            bytes = padded;
        }

        return Codecs.BASE64_URL_ENCODER.encodeToString(bytes);
    }
}
