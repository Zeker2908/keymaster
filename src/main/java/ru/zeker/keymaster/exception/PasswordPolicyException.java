package ru.zeker.keymaster.exception;

import ru.zeker.keymaster.domain.PasswordViolation;
import ru.zeker.keymaster.exception.dto.ErrorDetail;

import java.util.List;

public class PasswordPolicyException extends KeyMasterException {

    public PasswordPolicyException(List<PasswordViolation> violations) {
        super(
                ErrorCode.PASSWORD_POLICY_VIOLATION,
                ErrorCode.PASSWORD_POLICY_VIOLATION.getDefaultMessage(),
                violations.stream()
                        .map(violation -> new ErrorDetail("password", violation.name()))
                        .toList()
        );
    }
}
