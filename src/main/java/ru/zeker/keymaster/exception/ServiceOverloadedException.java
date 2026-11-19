package ru.zeker.keymaster.exception;

import java.time.Duration;

public class ServiceOverloadedException extends KeyMasterException {

    public static final Duration RETRY_AFTER = Duration.ofSeconds(2);

    public ServiceOverloadedException(Throwable cause) {
        super(ErrorCode.SERVICE_OVERLOADED, cause, RETRY_AFTER);
    }
}
