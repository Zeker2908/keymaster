package ru.zeker.keymaster.service;

import io.quarkus.hibernate.reactive.panache.Panache;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import ru.zeker.keymaster.domain.AuditAction;
import ru.zeker.keymaster.domain.context.Actor;
import ru.zeker.keymaster.domain.entity.Role;
import ru.zeker.keymaster.dto.request.NewRoleRequest;
import ru.zeker.keymaster.dto.response.RoleDetailsResponse;
import ru.zeker.keymaster.exception.ErrorCode;
import ru.zeker.keymaster.exception.KeyMasterException;
import ru.zeker.keymaster.mapper.RoleMapper;
import ru.zeker.keymaster.repository.RoleRepository;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

@Slf4j
@ApplicationScoped
@RequiredArgsConstructor
public class RoleService {

    private final RoleRepository roles;
    private final AuditService audits;
    private final RoleMapper mapper;

    public Uni<Role> findByName(String name) {
        return roles.findByName(name);
    }

    public Uni<Role> lockByName(String name) {
        return roles.lockByName(name);
    }

    public Uni<RoleDetailsResponse> create(Actor actor, NewRoleRequest request) {
        log.info("Creating role '{}'", request.name());
        return Panache.withTransaction(() -> roles.create(mapper.toEntity(request))
                .call(role -> audits.recordRole(actor, AuditAction.ROLE_CREATED, role))
                .map(mapper::toResponse)
                .invoke(response -> log.info("Role '{}' created with id {}", response.name(), response.id())));
    }

    public Uni<List<Role>> resolve(Collection<String> rawNames) {
        List<String> names = normalize(rawNames);
        if (names.isEmpty()) {
            return Uni.createFrom().item(List.of());
        }

        return roles.findByNameIn(names).map(found -> {
            Map<String, Role> byName = found.stream()
                    .collect(Collectors.toMap(Role::getName, Function.identity()));

            List<String> missing = names.stream()
                    .filter(name -> !byName.containsKey(name))
                    .toList();
            if (!missing.isEmpty()) {
                throw new KeyMasterException(ErrorCode.UNKNOWN_ROLE,
                        "Unknown role(s): " + String.join(", ", missing));
            }
            return names.stream().map(byName::get).toList();
        });
    }

    private static List<String> normalize(Collection<String> names) {
        if (names == null) {
            return List.of();
        }
        return names.stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(StringUtils::isNotEmpty)
                .distinct()
                .toList();
    }
}
