package ru.zeker.keymaster.service.password;

import jakarta.enterprise.context.ApplicationScoped;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import ru.zeker.keymaster.domain.PasswordViolation;
import ru.zeker.keymaster.util.Secrets;

import java.util.ArrayList;
import java.util.List;

@ApplicationScoped
@RequiredArgsConstructor
public final class PasswordPolicy {

    private static final int MIN_LENGTH = 15;
    private static final int MAX_LENGTH = 64;

    public List<PasswordViolation> validate(String login, char[] password) {
        char[] normalized = Secrets.normalize(password);
        try {
            return validateNormalized(login, normalized);
        } finally {
            Secrets.wipe(normalized);
        }
    }

    private List<PasswordViolation> validateNormalized(String login, char[] password) {
        List<PasswordViolation> violations = new ArrayList<>();

        if (password.length < MIN_LENGTH) violations.add(PasswordViolation.TOO_SHORT);
        if (password.length > MAX_LENGTH) violations.add(PasswordViolation.TOO_LONG);

        if (StringUtils.isNotEmpty(login) && passwordEqualsLogin(login, password)) {
            violations.add(PasswordViolation.EQUALS_LOGIN);
        }

        if (!violations.isEmpty()) return violations;

        boolean hasLetter = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;
        boolean hasInvalidCharacter = false;

        for (char c : password) {
            if (Character.isLetter(c)) hasLetter = true;
            else if (Character.isDigit(c)) hasDigit = true;
            else if (isSpecial(c)) hasSpecial = true;
            else hasInvalidCharacter = true;
        }

        if (!hasLetter) violations.add(PasswordViolation.NO_LETTER);
        if (!hasDigit) violations.add(PasswordViolation.NO_DIGIT);
        if (!hasSpecial) violations.add(PasswordViolation.NO_SPECIAL);
        if (hasInvalidCharacter) violations.add(PasswordViolation.INVALID_CHARACTER);

        return violations;
    }

    private boolean passwordEqualsLogin(String login, char[] password) {
        if (login.length() != password.length) return false;

        for (int i = 0; i < password.length; i++) {
            if (Character.toLowerCase(password[i]) != login.charAt(i)) return false;
        }

        return true;
    }

    private boolean isSpecial(char c) {
        return "!@#$%^&*()-_=+[]{};:,.?/\\".indexOf(c) >= 0;
    }
}