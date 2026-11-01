package ru.zeker.keymaster.resource.filter;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.ext.Provider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import ru.zeker.keymaster.exception.ErrorCode;
import ru.zeker.keymaster.exception.KeyMasterException;

import java.util.Arrays;

@Slf4j
@Provider
@RequireAdmin
@RequiredArgsConstructor
public class RequireAdminFilter implements ContainerRequestFilter {

    private static final String USER_ID = "X-User-Id";
    private static final String USER_ROLES = "X-User-Roles";
    private static final String ADMIN = "admin";
    private static final String SEP = ",";

    @Override
    public void filter(ContainerRequestContext requestContext) {
        String userId = requestContext.getHeaderString(USER_ID);
        String rolesHeader = requestContext.getHeaderString(USER_ROLES);
        String path = requestContext.getUriInfo().getRequestUri().getRawPath();

        if (StringUtils.isBlank(userId)) {
            log.warn("Admin access denied: missing {} header, path={}", USER_ID, path);
            throw new KeyMasterException(ErrorCode.UNAUTHORIZED, "Missing or invalid user identity");
        }

        if (StringUtils.isBlank(rolesHeader)) {
            log.warn("Admin access denied: missing {} header, userId={}, path={}",
                    USER_ROLES, userId, path);
            throw new KeyMasterException(ErrorCode.UNAUTHORIZED, "Missing user roles");
        }

        if (!isAdmin(rolesHeader)) {
            log.warn("Admin access denied: user has no admin role, userId={}, path={}", userId, path);
            throw new KeyMasterException(ErrorCode.FORBIDDEN, "Admin role required");
        }

        log.debug("Admin access granted: userId={}, path={}", userId, path);
    }

    private boolean isAdmin(String rolesHeader) {
        return Arrays.stream(rolesHeader.split(SEP))
                .map(String::trim)
                .anyMatch(ADMIN::equals);
    }
}
