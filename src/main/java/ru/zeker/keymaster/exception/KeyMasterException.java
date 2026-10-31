package ru.zeker.keymaster.exception;

import jakarta.ws.rs.core.Response;
import lombok.Getter;

@Getter
public class KeyMasterException extends RuntimeException {

    private final Response.Status status;

    public KeyMasterException(Response.Status status, String message, Throwable cause) {
        super(message, cause);
        this.status = status;
    }

    public KeyMasterException(Response.Status status, String message) {
        super(message);
        this.status = status;
    }
}
