package ru.zeker.keymaster.exception.mapper;

import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import lombok.extern.slf4j.Slf4j;
import ru.zeker.keymaster.exception.ErrorResponseFactory;

@Slf4j
@Provider
public class GlobalExceptionMapper implements ExceptionMapper<Exception> {

    @Context
    UriInfo uriInfo;

    @Override
    public Response toResponse(Exception exception) {
        log.error("Unhandled exception while processing request: {}", uriInfo.getRequestUri().getRawPath(), exception);

        return ErrorResponseFactory.create(
                Response.Status.INTERNAL_SERVER_ERROR,
                "Internal server error",
                uriInfo
        );
    }
}