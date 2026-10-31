package ru.zeker.keymaster.exception.mapper;

import jakarta.validation.ConstraintViolationException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import lombok.extern.slf4j.Slf4j;
import ru.zeker.keymaster.exception.ErrorResponseFactory;
import ru.zeker.keymaster.exception.dto.ErrorDetail;

import java.util.List;

@Slf4j
@Provider
public class ValidationExceptionMapper implements ExceptionMapper<ConstraintViolationException> {

    @Context
    UriInfo uriInfo;

    @Override
    public Response toResponse(ConstraintViolationException exception) {
        List<ErrorDetail> details = exception.getConstraintViolations().stream()
                .map(v -> new ErrorDetail(v.getPropertyPath().toString(), v.getMessage()))
                .toList();

        log.warn("Validation failed for request: {} ({} violations)", uriInfo.getRequestUri().getRawPath(), details.size());

        return ErrorResponseFactory.create(
                Response.Status.BAD_REQUEST,
                "Validation failed",
                details,
                uriInfo
        );
    }
}
