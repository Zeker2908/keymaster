package ru.zeker.keymaster.mapper.jwk;

import jakarta.enterprise.context.ApplicationScoped;
import ru.zeker.keymaster.domain.Algorithm;

@ApplicationScoped
public class Rs512JwkMapper extends RsaJwkMapper {

    @Override
    public Algorithm supports() {
        return Algorithm.RS512;
    }
}
