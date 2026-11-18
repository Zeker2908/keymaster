package ru.zeker.keymaster.service.jwt;

import jakarta.enterprise.context.ApplicationScoped;
import ru.zeker.keymaster.domain.key.codec.Codecs;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;

@ApplicationScoped
public class RefreshTokenFactory {
    private static final int TOKEN_BYTES = 32;

    private final SecureRandom random = new SecureRandom();

    public String generate() {
        byte[] bytes = new byte[TOKEN_BYTES];
        random.nextBytes(bytes);
        return Codecs.BASE64_URL_ENCODER.encodeToString(bytes);
    }

    public String hash(String token) {
        try {
            byte[] digest = MessageDigest.getInstance(Codecs.SHA_256)
                    .digest(token.getBytes(StandardCharsets.UTF_8));

            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
