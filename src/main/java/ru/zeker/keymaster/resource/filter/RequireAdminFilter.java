package ru.zeker.keymaster.resource.filter;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import ru.zeker.keymaster.domain.UserContext;

import java.util.Arrays;
import java.util.UUID;

@Slf4j
@Provider
@RequireAdmin
@RequiredArgsConstructor
public class RequireAdminFilter implements ContainerRequestFilter {

    private static final String USER_ID = "X-User-Id";
    private static final String USER_ROLES = "X-User-Roles";
    private static final String ADMIN = "admin";
    private static final String SEP = ",";

    private final UserContext userContext;

    @Override
    public void filter(ContainerRequestContext requestContext) {
        String userId = requestContext.getHeaderString(USER_ID);
        String rolesHeader = requestContext.getHeaderString(USER_ROLES);

        if (StringUtils.isBlank(userId) || !isUuid(userId)) {
            log.warn("Admin access denied: missing or invalid {} header, path={}", USER_ID,
                    requestContext.getUriInfo().getRequestUri().getRawPath());
            unauthorized(requestContext);
            return;
        }

        if (StringUtils.isBlank(rolesHeader)) {
            log.warn("Admin access denied: missing {} header, userId={}, path={}", USER_ROLES, userId,
                    requestContext.getUriInfo().getRequestUri().getRawPath());
            unauthorized(requestContext);
            return;
        }

        if (!isAdmin(rolesHeader)) {
            log.warn("Admin access denied: user has no admin role, userId={}, roles={}, path={}",
                    userId, rolesHeader, requestContext.getUriInfo().getRequestUri().getRawPath());
            forbidden(requestContext);
            return;
        }

        userContext.setUserId(UUID.fromString(userId));

        log.debug("Admin access granted: userId={}, path={}", userId,
                requestContext.getUriInfo().getRequestUri().getRawPath());
    }

    private boolean isAdmin(String rolesHeader) {
        return Arrays.stream(rolesHeader.split(SEP))
                .map(String::trim)
                .anyMatch(ADMIN::equals);
    }

    private boolean isUuid(String uuid) {
        try {
            UUID.fromString(uuid);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private void unauthorized(ContainerRequestContext context) {
        abort(context, Response.Status.UNAUTHORIZED);
    }

    private void forbidden(ContainerRequestContext context) {
        abort(context, Response.Status.FORBIDDEN);
    }

    private void abort(ContainerRequestContext context, Response.Status status) {
        context.abortWith(Response.status(status).build());
    }
}
