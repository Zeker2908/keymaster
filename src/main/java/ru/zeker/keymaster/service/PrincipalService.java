package ru.zeker.keymaster.service;

import io.quarkus.hibernate.reactive.panache.Panache;
import io.smallrye.mutiny.Multi;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import ru.zeker.keymaster.domain.AuditAction;
import ru.zeker.keymaster.domain.PasswordViolation;
import ru.zeker.keymaster.domain.context.Actor;
import ru.zeker.keymaster.domain.entity.Principal;
import ru.zeker.keymaster.domain.entity.Role;
import ru.zeker.keymaster.dto.request.NewUserRequest;
import ru.zeker.keymaster.dto.response.UserResponse;
import ru.zeker.keymaster.exception.ErrorCode;
import ru.zeker.keymaster.exception.KeyMasterException;
import ru.zeker.keymaster.exception.PasswordPolicyException;
import ru.zeker.keymaster.mapper.PrincipalMapper;
import ru.zeker.keymaster.repository.CredentialRepository;
import ru.zeker.keymaster.repository.PrincipalRepository;
import ru.zeker.keymaster.repository.PrincipalRoleRepository;
import ru.zeker.keymaster.service.password.PasswordHasher;
import ru.zeker.keymaster.service.password.PasswordPolicy;
import ru.zeker.keymaster.util.AuditDetails;
import ru.zeker.keymaster.util.UniqueViolations;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Slf4j
@ApplicationScoped
@RequiredArgsConstructor
public class PrincipalService {

    private static final Map<String, ErrorCode> UNIQUE_ERRORS = Map.of(
            Principal.LOGIN_UQ, ErrorCode.LOGIN_ALREADY_EXISTS
    );

    private final PrincipalRepository principals;
    private final CredentialRepository credentials;
    private final PrincipalRoleRepository principalRoles;
    private final RoleResolver roleResolver;
    private final AuditService auditService;
    private final PrincipalMapper mapper;
    private final PasswordPolicy policy;
    private final PasswordHasher hasher;

    public Uni<UserResponse> create(Actor actor, NewUserRequest request) {
        log.info("Creating user '{}'", request.login());

        List<PasswordViolation> violations = policy.validate(request.login(), request.password());
        if (!violations.isEmpty()) {
            log.warn("Password policy violated for user '{}', violations={}", request.login(), violations);
            Arrays.fill(request.password(), '\0');
            return Uni.createFrom().failure(new PasswordPolicyException(violations));
        }

        return hasher.hash(request.password())
                .chain(hash -> Panache.withTransaction(() -> persistUser(actor, request, hash)))
                .onFailure().transform(this::translate)
                .invoke(response -> log.info("User '{}' created, id={}", response.login(), response.id()));
    }

    private Uni<UserResponse> persistUser(Actor actor, NewUserRequest request, String hash) {
        return roleResolver.resolve(request.roles())
                .chain(resolved -> {
                    log.debug("Resolved {} role(s) for user '{}': {}",
                            resolved.size(), request.login(), roleNames(resolved));

                    Principal principal = mapper.toUser(request);

                    return principals.persist(principal)
                            .invoke(() -> log.debug("Principal persisted for user '{}', id={}",
                                    principal.getLogin(), principal.getId()))
                            .call(() -> auditService.recordUser(actor, AuditAction.USER_CREATED, principal,
                                    AuditDetails.userCreated(principal.getLogin(), resolved)))
                            .chain(() -> credentials.persist(mapper.toCredential(principal, hash)))
                            .invoke(() -> log.debug("Credential persisted for user '{}'", principal.getLogin()))
                            .chain(() -> assignRoles(actor, principal, resolved))
                            .map(applied -> mapper.toResponse(principal, applied));
                });
    }

    private Uni<List<Role>> assignRoles(Actor actor, Principal principal, List<Role> resolved) {
        return Multi.createFrom().iterable(resolved)
                .onItem().transformToUniAndConcatenate(role -> linkRole(actor, principal, role))
                .collect().asList();
    }

    private Uni<Role> linkRole(Actor actor, Principal principal, Role role) {
        return principalRoles.persist(mapper.toPrincipalRole(principal, role))
                .invoke(() -> log.debug("Role '{}' linked to user '{}'",
                        role.getName(), principal.getLogin()))
                .call(() -> auditService.recordUser(actor, AuditAction.ROLE_ASSIGNED, principal,
                        AuditDetails.roleAssigned(role)))
                .replaceWith(role);
    }

    private Throwable translate(Throwable failure) {
        Optional<String> constraint = UniqueViolations.constraintName(failure);
        ErrorCode code = constraint.map(UNIQUE_ERRORS::get).orElse(null);

        if (code == null) {
            log.debug("No error code mapped for failure type: {}", failure.getClass().getSimpleName());
            return failure;
        }

        log.warn("Unique constraint '{}' mapped to error code {}", constraint.orElse("unknown"), code);
        return new KeyMasterException(code, failure);
    }

    private static List<String> roleNames(List<Role> roles) {
        return roles.stream().map(Role::getName).toList();
    }
}
