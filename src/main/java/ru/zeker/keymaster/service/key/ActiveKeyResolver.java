package ru.zeker.keymaster.service.key;

import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import lombok.RequiredArgsConstructor;
import ru.zeker.keymaster.domain.key.SigningKeyData;

@ApplicationScoped
@RequiredArgsConstructor
public class ActiveKeyResolver {

    private final SigningKeyService signingKeys;
    private final SigningKeyCache cache;

    public Uni<SigningKeyData> activeKey() {
        return signingKeys.findActive()
                .chain(cache::get);
    }
}
