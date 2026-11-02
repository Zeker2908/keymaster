package ru.zeker.keymaster.service.password;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import ru.zeker.keymaster.domain.PasswordViolation;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PasswordPolicyTest {

    private final PasswordPolicy policy = new PasswordPolicy();

    @ParameterizedTest
    @CsvSource({
            "14, TOO_SHORT",
            "15, NONE",
            "64, NONE",
            "65, TOO_LONG"
    })
    void shouldValidatePasswordLength(int length, String expected) {
        List<PasswordViolation> violations = policy.validate(null, validPassword(length));

        if ("NONE".equals(expected)) {
            assertTrue(violations.isEmpty());
        } else {
            assertEquals(List.of(PasswordViolation.valueOf(expected)), violations);
        }
    }

    @Test
    void shouldRejectSpaces() {
        char[] password = "Aa1!abcdefghijk ".toCharArray();

        assertTrue(policy.validate(null, password)
                .contains(PasswordViolation.INVALID_CHARACTER));
    }

    @Test
    void shouldAcceptCyrillicLetters() {
        char[] password = "Яя1!абвгдежзийк".toCharArray();

        assertTrue(policy.validate(null, password).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"admin", "ADMIN", "Admin"})
    void shouldRejectPasswordEqualToLoginIgnoringCase(String password) {
        assertTrue(policy.validate("admin", password.toCharArray())
                .contains(PasswordViolation.EQUALS_LOGIN));
    }

    @Test
    void shouldAcceptPasswordDifferentFromLogin() {
        assertFalse(policy.validate("admin", "Admin123!Abcde".toCharArray())
                .contains(PasswordViolation.EQUALS_LOGIN));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void shouldSkipLoginComparison(String login) {
        assertFalse(policy.validate(login, "Password123!Abcde".toCharArray())
                .contains(PasswordViolation.EQUALS_LOGIN));
    }

    @Test
    void shouldRejectPasswordWithoutDigit() {
        assertTrue(policy.validate(null, "Password!Abcdefg".toCharArray())
                .contains(PasswordViolation.NO_DIGIT));
    }

    @Test
    void shouldRejectPasswordWithoutSpecialCharacter() {
        assertTrue(policy.validate(null, "Password123Abcde".toCharArray())
                .contains(PasswordViolation.NO_SPECIAL));
    }

    private char[] validPassword(int length) {
        return ("Aa1!" + "a".repeat(length - 4)).toCharArray();
    }
}
