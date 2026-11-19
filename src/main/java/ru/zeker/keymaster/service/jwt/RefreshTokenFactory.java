package ru.zeker.keymaster.service.jwt;

import jakarta.enterprise.context.ApplicationScoped;
import ru.zeker.keymaster.domain.Consts;

import java.security.SecureRandom;

@ApplicationScoped
public class RefreshTokenFactory {
    private static final int TOKEN_BYTES = 32;

    private final SecureRandom random = new SecureRandom();

    public String generate() {
        byte[] bytes = new byte[TOKEN_BYTES];
        random.nextBytes(bytes);
        return Consts.BASE64_URL_ENCODER.encodeToString(bytes);
    }
}
