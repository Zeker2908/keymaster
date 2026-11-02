package ru.zeker.keymaster.resource.filter;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.container.PreMatching;
import jakarta.ws.rs.ext.Provider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import ru.zeker.keymaster.domain.context.RequestContext;

import java.util.UUID;
import java.util.regex.Pattern;

@Slf4j
@Provider
@PreMatching
@RequiredArgsConstructor
public class RequestContextFilter implements ContainerRequestFilter, ContainerResponseFilter {

    private static final String REQUEST_ID_HEADER = "X-Request-Id";
    private static final String USER_ID_HEADER = "X-User-Id";
    private static final String MDC_KEY_REQUEST_ID = "requestId";
    private static final String MDC_KEY_USER_ID = "userId";
    private static final String REQUEST_START_TIME = "requestStartTime";
    private static final Pattern VALID_REQUEST_ID = Pattern.compile("[a-zA-Z0-9._-]{1,128}");

    private final RequestContext requestContext;

    @Override
    public void filter(ContainerRequestContext request) {
        long startTime = System.nanoTime();
        request.setProperty(REQUEST_START_TIME, startTime);

        String requestId = request.getHeaderString(REQUEST_ID_HEADER);

        if (requestId == null || !VALID_REQUEST_ID.matcher(requestId).matches()) {
            requestId = UUID.randomUUID().toString();
        }

        requestContext.setRequestId(requestId);
        MDC.put(MDC_KEY_REQUEST_ID, requestId);
        request.setProperty(REQUEST_ID_HEADER, requestId);

        String userId = request.getHeaderString(USER_ID_HEADER);

        if (userId != null) {
            try {
                requestContext.setUserId(UUID.fromString(userId));
                MDC.put(MDC_KEY_USER_ID, userId);
            } catch (IllegalArgumentException e) {
                requestContext.setUserId(null);
                MDC.remove(MDC_KEY_USER_ID);
            }
        }

        log.info("HTTP request started: method={} path={}",
                request.getMethod(),
                request.getUriInfo().getRequestUri().getRawPath());
    }

    @Override
    public void filter(ContainerRequestContext request, ContainerResponseContext response) {
        String requestId = (String) request.getProperty(REQUEST_ID_HEADER);

        if (requestId != null) {
            response.getHeaders().putSingle(REQUEST_ID_HEADER, requestId);
        }

        long startTime = (long) request.getProperty(REQUEST_START_TIME);
        long duration = (System.nanoTime() - startTime) / 1_000_000;

        log.info("HTTP request finished: method={} path={} status={} duration={}ms",
                request.getMethod(),
                request.getUriInfo().getRequestUri().getRawPath(),
                response.getStatus(),
                duration);

        MDC.remove(MDC_KEY_REQUEST_ID);
        MDC.remove(MDC_KEY_USER_ID);
    }
}
