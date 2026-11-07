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
import ru.zeker.keymaster.util.Secrets;

import java.util.List;
import java.util.UUID;

@Slf4j
@ApplicationScoped
@RequiredArgsConstructor
public class PrincipalService {

    private static final String ADMIN_ROLE = "admin";

    private final PrincipalRepository principals;
    private final CredentialRepository credentials;
    private final PrincipalRoleRepository principalRoles;
    private final RoleService roles;
    private final AuditService audits;
    private final PrincipalMapper mapper;
    private final PasswordPolicy policy;
    private final PasswordHasher hasher;

    public Uni<UserResponse> create(Actor actor, NewUserRequest request) {
        log.info("Creating user '{}'", request.login());

        List<PasswordViolation> violations = policy.validate(request.login(), request.password());
        if (!violations.isEmpty()) {
            log.warn("Password policy violated for user '{}', violations={}", request.login(), violations);
            Secrets.wipe(request.password());
            return Uni.createFrom().failure(new PasswordPolicyException(violations));
        }

        return hasher.hash(request.password())
                .chain(hash -> Panache.withTransaction(() -> persistUser(actor, request, hash)))
                .invoke(response -> log.info("User '{}' created, id={}", response.login(), response.id()));
    }

    public Uni<UserResponse> getById(UUID id) {
        log.info("Searching for user, id={}", id);
        return Panache.withSession(() -> principals.findById(id)
                .onItem().ifNull().failWith(() ->
                        new KeyMasterException(ErrorCode.USER_NOT_FOUND))
                .chain(principal -> principalRoles.findRolesByPrincipalId(id)
                        .map(userRoles -> mapper.toResponse(principal, userRoles)))
                .invoke(() -> log.info("User found, id={}", id)));
    }

    public Uni<Void> assignRole(Actor actor, UUID userId, String roleName) {
        log.info("Assigning role '{}' to user id={}", roleName, userId);

        return Panache.withTransaction(() -> principals.findById(userId)
                        .onItem().ifNull().failWith(() ->
                                new KeyMasterException(ErrorCode.USER_NOT_FOUND))
                        .chain(principal -> roles.findByName(roleName)
                                .onItem().ifNull().failWith(() ->
                                        new KeyMasterException(ErrorCode.ROLE_NOT_FOUND))
                                .chain(role -> linkRole(actor, principal, role).replaceWithVoid())))
                .replaceWithVoid();
    }

    public Uni<Void> revokeRole(Actor actor, UUID userId, String roleName) {
        log.info("Revoking role '{}' from user id={}", roleName, userId);

        return Panache.withTransaction(() -> principals.findById(userId)
                .onItem().ifNull().failWith(() ->
                        new KeyMasterException(ErrorCode.USER_NOT_FOUND))
                .chain(principal -> roles.findByName(roleName)
                        .onItem().ifNull().failWith(() ->
                                new KeyMasterException(ErrorCode.ROLE_NOT_FOUND))
                        .chain(role -> revokeWithAdminGuard(actor, principal, role))));
    }

    private Uni<Void> revokeWithAdminGuard(Actor actor, Principal principal, Role role) {
        if (!ADMIN_ROLE.equals(role.getName())) {
            return unlinkRole(actor, principal, role);
        }

        return roles.lockByName(ADMIN_ROLE)
                .chain(ignored -> principalRoles.existsByPrincipalIdAndRoleId(principal.getId(), role.getId()))
                .chain(assigned -> {
                    if (!assigned) {
                        return Uni.createFrom().voidItem();
                    }
                    return principalRoles.countActiveByRoleIdExcludingPrincipal(role.getId(), principal.getId())
                            .chain(remaining -> remaining > 0
                                    ? unlinkRole(actor, principal, role)
                                    : Uni.createFrom().failure(new KeyMasterException(ErrorCode.LAST_ADMIN)));
                });
    }

    private Uni<Void> unlinkRole(Actor actor, Principal principal, Role role) {
        return principalRoles.deleteByPrincipalIdAndRoleId(principal.getId(), role.getId())
                .invoke(deleted -> log.debug("Role '{}' revoked from user '{}' (deleted={})",
                        role.getName(), principal.getLogin(), deleted))
                .chain(deleted -> deleted > 0
                        ? audits.recordUser(actor, AuditAction.ROLE_REVOKED, principal,
                        AuditDetails.roleRevoked(role))
                        : Uni.createFrom().voidItem());
    }

    private Uni<UserResponse> persistUser(Actor actor, NewUserRequest request, String hash) {
        return roles.resolve(request.roles())
                .chain(resolved -> {
                    log.debug("Resolved {} role(s) for user '{}': {}",
                            resolved.size(), request.login(), roleNames(resolved));

                    Principal principal = mapper.toUser(request);

                    return principals.create(principal)
                            .invoke(() -> log.debug("Principal persisted for user '{}', id={}",
                                    principal.getLogin(), principal.getId()))
                            .call(() -> audits.recordUser(actor, AuditAction.USER_CREATED, principal,
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
        return principalRoles.assign(principal.getId(), role.getId())
                .invoke(assigned -> log.debug("Role '{}' {} user '{}'",
                        role.getName(), assigned ? "linked to" : "already linked to", principal.getLogin()))
                .chain(assigned -> assigned
                        ? audits.recordUser(actor, AuditAction.ROLE_ASSIGNED, principal,
                        AuditDetails.roleAssigned(role))
                        : Uni.createFrom().voidItem())
                .replaceWith(role);
    }

    private static List<String> roleNames(List<Role> roles) {
        return roles.stream().map(Role::getName).toList();
    }
}
