package ru.zeker.keymaster.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    LOGIN_ALREADY_EXISTS("LOGIN_ALREADY_EXISTS", 409, "Login already exists"),
    UNKNOWN_ROLE("UNKNOWN_ROLE", 400, "Unknown role"),
    PASSWORD_POLICY_VIOLATION("PASSWORD_POLICY_VIOLATION", 400, "Password does not meet the policy"),
    SERVICE_OVERLOADED("SERVICE_OVERLOADED", 503, "Password hashing capacity exceeded"),
    UNAUTHORIZED("UNAUTHORIZED", 401, "Authentication required"),
    FORBIDDEN("FORBIDDEN", 403, "Admin role required");

    private final String code;
    private final int status;
    private final String defaultMessage;
}
