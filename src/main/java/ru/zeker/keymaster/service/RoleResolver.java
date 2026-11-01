package ru.zeker.keymaster.service;

import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import ru.zeker.keymaster.domain.entity.Role;
import ru.zeker.keymaster.exception.ErrorCode;
import ru.zeker.keymaster.exception.KeyMasterException;
import ru.zeker.keymaster.repository.RoleRepository;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

@ApplicationScoped
@RequiredArgsConstructor
public class RoleResolver {

    private final RoleRepository roles;

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
