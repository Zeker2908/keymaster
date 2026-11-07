package ru.zeker.keymaster.exception.mapper;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.validation.ConstraintViolationException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jboss.resteasy.reactive.server.ServerExceptionMapper;
import ru.zeker.keymaster.exception.ErrorResponseFactory;
import ru.zeker.keymaster.exception.KeyMasterException;
import ru.zeker.keymaster.exception.ServiceOverloadedException;
import ru.zeker.keymaster.exception.dto.ErrorDetail;
import ru.zeker.keymaster.exception.dto.ErrorResponse;

import java.util.List;

@Slf4j
@ApplicationScoped
@RequiredArgsConstructor
public class GlobalExceptionMapper {

    private static final String RETRY_AFTER = "Retry-After";
    private static final String RETRY_AFTER_SECONDS = "2";

    private final ErrorResponseFactory errorResponseFactory;

    @ServerExceptionMapper
    public Response handleServiceOverloaded(ServiceOverloadedException exception, UriInfo uriInfo) {
        log.warn("Overloaded exception for request: {} - {}", path(uriInfo), exception.getMessage());

        return Response.status(exception.getCode().getStatus())
                .type(MediaType.APPLICATION_JSON_TYPE)
                .header(RETRY_AFTER, RETRY_AFTER_SECONDS)
                .entity(errorResponseFactory.createBody(
                        exception.getCode().getStatus(),
                        exception.getCode().name(),
                        exception.getMessage(),
                        exception.getDetails(),
                        uriInfo
                ))
                .build();
    }

    @ServerExceptionMapper
    public Response handleKeyMaster(KeyMasterException exception, UriInfo uriInfo) {
        log.warn("Keymaster exception for request: {} - {}", path(uriInfo), exception.getMessage());

        return errorResponseFactory.create(
                exception.getCode().getStatus(),
                exception.getCode().name(),
                exception.getMessage(),
                exception.getDetails(),
                uriInfo
        );
    }

    @ServerExceptionMapper
    public Response handleValidation(ConstraintViolationException exception, UriInfo uriInfo) {
        List<ErrorDetail> details = exception.getConstraintViolations().stream()
                .map(v -> new ErrorDetail(v.getPropertyPath().toString(), v.getMessage()))
                .toList();

        log.warn("Validation failed for request: {} ({} violations)", path(uriInfo), details.size());

        return errorResponseFactory.create(
                Response.Status.BAD_REQUEST,
                "Validation failed",
                details,
                uriInfo
        );
    }

    @ServerExceptionMapper
    public Response handleWebApplication(WebApplicationException exception, UriInfo uriInfo) {
        Response originalResponse = exception.getResponse();
        int statusCode = originalResponse.getStatus();
        Response.Status status = Response.Status.fromStatusCode(statusCode);
        String path = path(uriInfo);

        if (statusCode >= 500) {
            log.error("HTTP {} while processing request: {}", statusCode, path, exception);
        } else {
            log.warn("HTTP {} while processing request: {}", statusCode, path);
        }

        ErrorResponse body = errorResponseFactory.createBody(
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

    @ServerExceptionMapper
    public Response handleUnexpected(Throwable exception, UriInfo uriInfo) {
        log.error("Unhandled exception while processing request: {}", path(uriInfo), exception);

        return errorResponseFactory.create(
                Response.Status.INTERNAL_SERVER_ERROR,
                "Internal server error",
                uriInfo
        );
    }

    private String path(UriInfo uriInfo) {
        return uriInfo.getRequestUri().getRawPath();
    }
}
