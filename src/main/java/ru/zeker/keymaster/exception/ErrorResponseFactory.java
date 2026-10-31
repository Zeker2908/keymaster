package ru.zeker.keymaster.exception;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import lombok.experimental.UtilityClass;
import org.slf4j.MDC;
import ru.zeker.keymaster.domain.Const;
import ru.zeker.keymaster.exception.dto.ErrorDetail;
import ru.zeker.keymaster.exception.dto.ErrorResponse;

import java.time.Instant;
import java.util.List;

@UtilityClass
public final class ErrorResponseFactory {

    public static Response create(Response.Status status, String message, UriInfo uriInfo) {
        return create(status, message, List.of(), uriInfo);
    }

    public static Response create(Response.Status status, String message, List<ErrorDetail> details, UriInfo uriInfo) {
        return Response.status(status)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .entity(createBody(status.getStatusCode(), status.getReasonPhrase(), message, details, uriInfo))
                .build();
    }

    public static Response create(int status, String error, String message, UriInfo uriInfo) {
        return Response.status(status)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .entity(createBody(status, error, message, List.of(), uriInfo))
                .build();
    }

    public static ErrorResponse createBody(int status, String error, String message, List<ErrorDetail> details, UriInfo uriInfo) {
        return new ErrorResponse(
                Instant.now(),
                status,
                error,
                message,
                uriInfo.getRequestUri().getPath(),
                details,
                MDC.get(Const.MDC_KEY_REQUEST_ID)
        );
    }

    public static ErrorResponse createBody(Response.Status status, String message, List<ErrorDetail> details, UriInfo uriInfo) {
        return new ErrorResponse(
                Instant.now(),
                status.getStatusCode(),
                status.getReasonPhrase(),
                message,
                uriInfo.getRequestUri().getPath(),
                details,
                MDC.get(Const.MDC_KEY_REQUEST_ID)
        );
    }
}
