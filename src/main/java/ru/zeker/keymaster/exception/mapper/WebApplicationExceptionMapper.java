package ru.zeker.keymaster.exception.mapper;

import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import lombok.extern.slf4j.Slf4j;
import ru.zeker.keymaster.exception.ErrorResponseFactory;
import ru.zeker.keymaster.exception.dto.ErrorResponse;

import java.util.List;

@Slf4j
@Provider
public class WebApplicationExceptionMapper implements ExceptionMapper<WebApplicationException> {

    @Context
    UriInfo uriInfo;

    @Override
    public Response toResponse(WebApplicationException exception) {
        Response originalResponse = exception.getResponse();
        int statusCode = originalResponse.getStatus();
        Response.Status status = Response.Status.fromStatusCode(statusCode);
        String path = uriInfo.getRequestUri().getRawPath();

        if (statusCode >= 500) {
            log.error("HTTP {} while processing request: {}", statusCode, path, exception);
        } else {
            log.warn("HTTP {} while processing request: {}", statusCode, path);
        }

        ErrorResponse body = ErrorResponseFactory.createBody(
                statusCode,
                status != null ? status.getReasonPhrase() : "HTTP Error",
                status != null ? status.getReasonPhrase() : "Request failed",
                List.of(),
                uriInfo
        );

        return Response.fromResponse(originalResponse)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .entity(body)
                .header("Content-Length", null)
                .build();
    }
}
