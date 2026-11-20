package ru.zeker.keymaster.service;

import org.apache.commons.lang3.StringUtils;
import ru.zeker.keymaster.domain.Patterns;
import ru.zeker.keymaster.util.Secrets;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Единая нормализация логина для поиска в БД и для счётчиков троттлинга.
 *
 * <p>Порядок важен: сначала NFKC, затем приведение к нижнему регистру,
 * затем проверка длины и шаблона. Иначе разные варианты одного и того же
 * логина могут попасть в разные счётчики или не найти существующего пользователя.</p>
 */
public final class LoginNormalizer {

    public static final int MAX_LENGTH = 32;

    private static final Pattern LOGIN = Pattern.compile(Patterns.LOGIN);

    private LoginNormalizer() {
    }

    /**
     * @return нормализованный логин или {@code null}, если он недопустим
     */
    public static String normalize(String raw) {
        if (StringUtils.isBlank(raw)) {
            return null;
        }

        String normalized = Secrets.normalize(raw).toLowerCase(Locale.ROOT).trim();

        if (normalized.length() > MAX_LENGTH || !LOGIN.matcher(normalized).matches()) {
            return null;
        }

        return normalized;
    }
}
