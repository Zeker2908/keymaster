package ru.zeker.keymaster.domain;

public enum PasswordViolation {
    TOO_SHORT,
    TOO_LONG,
    NO_LETTER,
    NO_DIGIT,
    NO_SPECIAL,
    INVALID_CHARACTER,
    COMMON_PASSWORD,
    EQUALS_LOGIN,
    COMPROMISED_PASSWORD
}