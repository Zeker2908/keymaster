package ru.zeker.keymaster.exception;

public class ServiceOverloadedException extends KeyMasterException {

    public ServiceOverloadedException(Throwable cause) {
        super(ErrorCode.SERVICE_OVERLOADED, cause);
    }
}
