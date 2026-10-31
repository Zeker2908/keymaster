package ru.zeker.keymaster.logging;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.container.PreMatching;
import jakarta.ws.rs.ext.Provider;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import ru.zeker.keymaster.domain.Const;

import java.util.UUID;
import java.util.regex.Pattern;

@Slf4j
@Provider
@PreMatching
public class RequestIdFilter implements ContainerRequestFilter, ContainerResponseFilter {

    private static final String HEADER = "X-Request-Id";
    private static final Pattern VALID_REQUEST_ID = Pattern.compile("[a-zA-Z0-9._-]{1,128}");

    @Override
    public void filter(ContainerRequestContext requestContext) {
        String requestId = requestContext.getHeaderString(HEADER);

        if (requestId == null || !VALID_REQUEST_ID.matcher(requestId).matches()) {
            requestId = UUID.randomUUID().toString();
        }

        requestContext.setProperty(Const.MDC_KEY_REQUEST_ID, requestId);
        MDC.put(Const.MDC_KEY_REQUEST_ID, requestId);
    }

    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) {
        String requestId = (String) requestContext.getProperty(Const.MDC_KEY_REQUEST_ID);

        if (requestId != null) {
            responseContext.getHeaders().putSingle(HEADER, requestId);
        }

        MDC.remove(Const.MDC_KEY_REQUEST_ID);
    }
}
