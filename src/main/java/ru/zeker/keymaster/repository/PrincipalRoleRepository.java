package ru.zeker.keymaster.repository;

import io.quarkus.hibernate.reactive.panache.PanacheRepositoryBase;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import ru.zeker.keymaster.domain.PrincipalStatus;
import ru.zeker.keymaster.domain.entity.PrincipalRole;
import ru.zeker.keymaster.domain.entity.PrincipalRoleId;
import ru.zeker.keymaster.domain.entity.Role;

import java.util.List;
import java.util.UUID;

@ApplicationScoped
public class PrincipalRoleRepository implements PanacheRepositoryBase<PrincipalRole, PrincipalRoleId> {

    public Uni<List<Role>> findRolesByPrincipalId(UUID principalId) {
        return find("select pr.role from PrincipalRole pr where pr.principal.id = ?1 order by pr.role.name",
                principalId)
                .project(Role.class)
                .list();
    }

    public Uni<Boolean> existsByPrincipalIdAndRoleId(UUID principalId, UUID roleId) {
        return count("principal.id = ?1 and role.id = ?2", principalId, roleId)
                .map(count -> count > 0);
    }

    public Uni<Boolean> existsActiveAdmin() {
        return count("role.name = ?1 and principal.status = ?2", "admin", PrincipalStatus.ACTIVE)
                .map(count -> count > 0);
    }

    public Uni<Long> countActiveByRoleIdExcludingPrincipal(UUID roleId, UUID principalId) {
        return count("role.id = ?1 and principal.status = ?2 and principal.id <> ?3",
                roleId, PrincipalStatus.ACTIVE, principalId);
    }

    public Uni<Long> deleteByPrincipalIdAndRoleId(UUID principalId, UUID roleId) {
        return delete("principal.id = ?1 and role.id = ?2", principalId, roleId);
    }
}
