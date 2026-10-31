package ru.zeker.keymaster.exception;

import jakarta.ws.rs.core.Response;

public class ServiceOverloadedException extends KeyMasterException {
    public ServiceOverloadedException(Throwable cause) {
        super(Response.Status.SERVICE_UNAVAILABLE, "Password hashing capacity exceeded", cause);
    }
}
