package ru.zeker.keymaster.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import ru.zeker.keymaster.domain.entity.Credential;
import ru.zeker.keymaster.domain.entity.Principal;
import ru.zeker.keymaster.domain.entity.PrincipalRole;
import ru.zeker.keymaster.domain.entity.Role;
import ru.zeker.keymaster.dto.request.NewClientRequest;
import ru.zeker.keymaster.dto.request.NewUserRequest;
import ru.zeker.keymaster.dto.response.RoleResponse;
import ru.zeker.keymaster.dto.response.UserResponse;

import java.util.List;

@Mapper
public interface PrincipalMapper {

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "kind", constant = "USER")
    @Mapping(target = "status", constant = "ACTIVE")
    Principal toUser(NewUserRequest request);

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "kind", constant = "CLIENT")
    @Mapping(target = "status", constant = "ACTIVE")
    @Mapping(target = "login", source = "name")
    Principal toClient(NewClientRequest request);

    @Mapping(target = "roles", source = "roles")
    UserResponse toResponse(Principal principal, List<Role> roles);

    @Mapping(target = "id", expression = "java(new ru.zeker.keymaster.domain.entity.PrincipalRoleId(principal.getId(), role.getId()))")
    @Mapping(target = "principal", source = "principal")
    @Mapping(target = "role", source = "role")
    @Mapping(target = "assignedAt", ignore = true)
    PrincipalRole toPrincipalRole(Principal principal, Role role);

    @Mapping(target = "principalId", source = "principal.id")
    @Mapping(target = "principal", source = "principal")
    @Mapping(target = "secretHash", source = "secretHash")
    @Mapping(target = "changedAt", ignore = true)
    Credential toCredential(Principal principal, String secretHash);

    RoleResponse toRoleResponse(Role role);
}
