package ru.zeker.keymaster.service;

import io.quarkus.hibernate.reactive.panache.Panache;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Validator;
import lombok.RequiredArgsConstructor;
import ru.zeker.keymaster.domain.context.Actor;
import ru.zeker.keymaster.dto.request.NewUserRequest;
import ru.zeker.keymaster.exception.ErrorCode;
import ru.zeker.keymaster.exception.KeyMasterException;
import ru.zeker.keymaster.repository.PrincipalRoleRepository;
import ru.zeker.keymaster.util.PasswordUtils;

import java.util.List;
import java.util.Set;

@ApplicationScoped
@RequiredArgsConstructor
public class BootstrapAdminService {

    private static final Actor SYSTEM = new Actor(null, "bootstrap");

    private final PrincipalService principals;
    private final PrincipalRoleRepository principalRoles;
    private final Validator validator;

    public Uni<Boolean> ensureAdmin(String login, String password) {
        return hasActiveAdmin()
                .chain(exists -> {
                    if (exists) return Uni.createFrom().item(false);

                    NewUserRequest request = new NewUserRequest(login, password.toCharArray(), List.of("admin"));
                    Set<ConstraintViolation<NewUserRequest>> violations = validator.validate(request);

                    if (!violations.isEmpty()) {
                        PasswordUtils.wipe(request.password());
                        return Uni.createFrom().failure(new ConstraintViolationException(violations));
                    }

                    return principals.create(SYSTEM, request)
                            .replaceWith(true)
                            .onFailure(this::isLoginConflict)
                            .recoverWithUni(this::failIfStillNoAdmin);
                });
    }

    private Uni<Boolean> hasActiveAdmin() {
        return Panache.withSession(principalRoles::existsActiveAdmin);
    }

    private boolean isLoginConflict(Throwable failure) {
        return failure instanceof KeyMasterException e
                && e.getCode() == ErrorCode.LOGIN_ALREADY_EXISTS;
    }

    private Uni<Boolean> failIfStillNoAdmin(Throwable failure) {
        return hasActiveAdmin().chain(exists -> exists
                ? Uni.createFrom().item(false)
                : Uni.createFrom().failure(new IllegalStateException(
                "Bootstrap admin login is already taken by a non-admin principal "
                        + "and no active admin exists. Change keymaster.bootstrap.admin.login.", failure)));
    }
}
