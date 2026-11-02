package ru.zeker.keymaster.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    LOGIN_ALREADY_EXISTS( 409, "Login already exists"),
    UNKNOWN_ROLE( 400, "Unknown role"),
    PASSWORD_POLICY_VIOLATION( 400, "Password does not meet the policy"),
    SERVICE_OVERLOADED( 503, "Password hashing capacity exceeded"),
    UNAUTHORIZED( 401, "Authentication required"),
    FORBIDDEN( 403, "Admin role required"),
    USER_NOT_FOUND( 404, "User not found"),
    ROLE_NOT_FOUND( 404, "Role not found"),
    LAST_ADMIN( 409, "Cannot revoke the last active administrator role"),
    ROLE_ALREADY_EXISTS( 409, "Role already exists");

    private final int status;
    private final String defaultMessage;
}
