package ru.zeker.keymaster.util;

import lombok.extern.slf4j.Slf4j;
import ru.zeker.keymaster.domain.entity.Principal;
import ru.zeker.keymaster.domain.entity.Role;
import ru.zeker.keymaster.domain.entity.SigningKey;
import ru.zeker.keymaster.exception.ErrorCode;
import ru.zeker.keymaster.exception.KeyMasterException;

import java.util.Map;
import java.util.Optional;

@Slf4j
public final class ExceptionTranslator {

    private static final Map<String, ErrorCode> ERROR_CODE_MAP = Map.of(
            Principal.LOGIN_UQ, ErrorCode.LOGIN_ALREADY_EXISTS,
            Role.ROLE_UQ, ErrorCode.ROLE_ALREADY_EXISTS,
            SigningKey.KEY_SCHEDULE_EXCL, ErrorCode.KEY_SCHEDULE_CONFLICT
    );

    private ExceptionTranslator() {
    }

    public static Throwable translate(Throwable failure) {
        Optional<String> constraint = DatabaseConstraintViolations.constraintName(
                        failure, DatabaseConstraintViolations.UNIQUE_VIOLATION)
                .or(() -> DatabaseConstraintViolations.constraintName(
                        failure, DatabaseConstraintViolations.EXCLUSION_VIOLATION));

        ErrorCode code = constraint.map(ERROR_CODE_MAP::get).orElse(null);

        if (code == null) {
            log.debug("No error code mapped for failure type: {}", failure.getClass().getSimpleName());
            return failure;
        }

        log.warn("Database constraint '{}' mapped to error code {}", constraint.orElse("unknown"), code);
        return new KeyMasterException(code, failure);
    }
}
