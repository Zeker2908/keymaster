package ru.zeker.keymaster.exception.mapper;

import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import lombok.extern.slf4j.Slf4j;
import ru.zeker.keymaster.exception.KeyMasterException;
import ru.zeker.keymaster.exception.ErrorResponseFactory;

@Slf4j
@Provider
public class KeyMasterExceptionMapper implements ExceptionMapper<KeyMasterException> {

    @Context
    UriInfo uriInfo;

    @Override
    public Response toResponse(KeyMasterException exception) {
        log.warn("Keymaster exception for request: {} - {}", uriInfo.getRequestUri().getRawPath(), exception.getMessage());

        return ErrorResponseFactory.create(
                exception.getStatus(),
                exception.getMessage(),
                uriInfo
        );
    }
}
