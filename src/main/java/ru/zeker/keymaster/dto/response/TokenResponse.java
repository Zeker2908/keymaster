package ru.zeker.keymaster.dto.response;

import io.quarkus.runtime.annotations.RegisterForReflection;

import java.time.Duration;

/**
 * Ответ на успешный вход.
 *
 * <p>Refresh-токена здесь нет до этапа 6: без хранения хэша, ротации и
 * обнаружения повторного использования его нельзя безопасно обменять.
 * Клиент не должен получать токен, который сервис не сможет принять.</p>
 */
@RegisterForReflection
public record TokenResponse(
        String accessToken,
        String tokenType,
        long expiresIn
) {
    public static TokenResponse of(String accessToken, Duration ttl) {
        return new TokenResponse(
                accessToken,
                "Bearer",
                ttl.toSeconds()
        );
    }
}
