package ru.zeker.keymaster.exception;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import lombok.RequiredArgsConstructor;
import ru.zeker.keymaster.domain.context.RequestContext;
import ru.zeker.keymaster.exception.dto.ErrorDetail;
import ru.zeker.keymaster.exception.dto.ErrorResponse;

import java.time.Clock;
import java.util.List;

@ApplicationScoped
@RequiredArgsConstructor
public class ErrorResponseFactory {

    private final RequestContext context;
    private final Clock clock;

    public Response create(Response.Status status, String message, UriInfo uriInfo) {
        return create(status, message, List.of(), uriInfo);
    }

    public Response create(Response.Status status, String message, List<ErrorDetail> details, UriInfo uriInfo) {
        return create(status.getStatusCode(), status.getReasonPhrase(), message, details, uriInfo);
    }

    public Response create(int status, String error, String message, UriInfo uriInfo) {
        return create(status, error, message, List.of(), uriInfo);
    }

    public Response create(int status, String error, String message, List<ErrorDetail> details, UriInfo uriInfo) {
        return Response.status(status)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .entity(createBody(status, error, message, details, uriInfo))
                .build();
    }

    public ErrorResponse createBody(int status, String error, String message, List<ErrorDetail> details, UriInfo uriInfo) {
        return new ErrorResponse(
                clock.instant(),
                status,
                error,
                message,
                uriInfo.getRequestUri().getPath(),
                details,
                context.getRequestId()
        );
    }

    public ErrorResponse createBody(Response.Status status, String message, List<ErrorDetail> details, UriInfo uriInfo) {
        return createBody(status.getStatusCode(), status.getReasonPhrase(), message, details, uriInfo);
    }
}
