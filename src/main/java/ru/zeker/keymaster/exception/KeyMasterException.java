package ru.zeker.keymaster.exception;

import lombok.Getter;
import ru.zeker.keymaster.exception.dto.ErrorDetail;

import java.time.Duration;
import java.util.List;

@Getter
public class KeyMasterException extends RuntimeException {

    private final ErrorCode code;
    private final List<ErrorDetail> details;
    private final Duration retryAfter;

    public KeyMasterException(ErrorCode code) {
        this(code, code.getDefaultMessage(), null, List.of(), null);
    }

    public KeyMasterException(ErrorCode code, Throwable cause) {
        this(code, code.getDefaultMessage(), cause, List.of(), null);
    }

    public KeyMasterException(ErrorCode code, Throwable cause, Duration retryAfter) {
        this(code, code.getDefaultMessage(), cause, List.of(), retryAfter);
    }

    public KeyMasterException(ErrorCode code, String message) {
        this(code, message, null, List.of(), null);
    }

    public KeyMasterException(ErrorCode code, String message, Throwable cause) {
        this(code, message, cause, List.of(), null);
    }

    public KeyMasterException(ErrorCode code, String message, List<ErrorDetail> details) {
        this(code, message, null, details, null);
    }

    public KeyMasterException(ErrorCode code, Duration retryAfter) {
        this(code, code.getDefaultMessage(), null, List.of(), retryAfter);
    }

    public KeyMasterException(ErrorCode code, String message, Throwable cause, List<ErrorDetail> details) {
        this(code, message, cause, details, null);
    }

    private KeyMasterException(
            ErrorCode code,
            String message,
            Throwable cause,
            List<ErrorDetail> details,
            Duration retryAfter
    ) {
        super(message, cause);
        this.code = code;
        this.details = details == null ? List.of() : List.copyOf(details);
        this.retryAfter = retryAfter;
    }
}
