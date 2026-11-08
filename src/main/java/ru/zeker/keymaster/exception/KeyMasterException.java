package ru.zeker.keymaster.exception;

import lombok.Getter;
import ru.zeker.keymaster.exception.dto.ErrorDetail;

import java.util.List;

@Getter
public class KeyMasterException extends RuntimeException {

    private final ErrorCode code;
    private final List<ErrorDetail> details;

    public KeyMasterException(ErrorCode code) {
        this(code, code.getDefaultMessage(), null, List.of());
    }

    public KeyMasterException(ErrorCode code, Throwable cause) {
        this(code, code.getDefaultMessage(), cause, List.of());
    }

    public KeyMasterException(ErrorCode code, String message) {
        this(code, message, null, List.of());
    }

    public KeyMasterException(ErrorCode code, String message, Throwable cause) {
        this(code, message, cause, List.of());
    }

    public KeyMasterException(ErrorCode code, String message, List<ErrorDetail> details) {
        this(code, message, null, details);
    }

    public KeyMasterException(ErrorCode code, String message, Throwable cause, List<ErrorDetail> details) {
        super(message, cause);
        this.code = code;
        this.details = details == null ? List.of() : List.copyOf(details);
    }
}
