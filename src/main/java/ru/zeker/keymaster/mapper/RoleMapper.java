package ru.zeker.keymaster.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import ru.zeker.keymaster.domain.entity.Role;
import ru.zeker.keymaster.dto.request.NewRoleRequest;
import ru.zeker.keymaster.dto.response.RoleDetailsResponse;

@Mapper
public interface RoleMapper {

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    Role toEntity(NewRoleRequest request);

    RoleDetailsResponse toResponse(Role entity);
}
