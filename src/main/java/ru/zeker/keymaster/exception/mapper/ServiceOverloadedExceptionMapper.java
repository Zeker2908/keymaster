package ru.zeker.keymaster.exception.mapper;

import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import lombok.extern.slf4j.Slf4j;
import ru.zeker.keymaster.exception.ErrorResponseFactory;
import ru.zeker.keymaster.exception.ServiceOverloadedException;
import ru.zeker.keymaster.exception.dto.ErrorResponse;

import java.util.List;

@Slf4j
@Provider
public class ServiceOverloadedExceptionMapper implements ExceptionMapper<ServiceOverloadedException> {

    @Context
    UriInfo uriInfo;

    @Override
    public Response toResponse(ServiceOverloadedException exception) {
        log.warn("Overloaded exception for request: {} - {}", uriInfo.getRequestUri().getRawPath(), exception.getMessage());

        ErrorResponse body = ErrorResponseFactory.createBody(
                exception.getStatus(),
                exception.getMessage(),
                List.of(),
                uriInfo
        );

        return Response.status(exception.getStatus())
                .type(MediaType.APPLICATION_JSON_TYPE)
                .entity(body)
                .header("Retry-After", "2")
                .build();
    }
}
