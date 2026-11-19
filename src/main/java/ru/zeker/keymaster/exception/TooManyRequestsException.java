package ru.zeker.keymaster.exception;

import java.time.Duration;

public class TooManyRequestsException extends KeyMasterException {

    public TooManyRequestsException(Duration retryAfter) {
        super(ErrorCode.TOO_MANY_REQUESTS, retryAfter);
    }
}
