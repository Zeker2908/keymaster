package ru.zeker.keymaster.domain;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public enum AuditAction {
    USER_CREATED("user.created"),
    ROLE_CREATED("role.created"),
    ROLE_ASSIGNED("role.assigned"),
    ROLE_REVOKED("role.revoked"),
    KEY_CREATED("key.created");

    private final String code;

    public String code() {
        return code;
    }
}
