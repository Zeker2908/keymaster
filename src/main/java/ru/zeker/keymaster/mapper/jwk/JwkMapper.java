package ru.zeker.keymaster.mapper.jwk;

import com.nimbusds.jose.jwk.JWK;
import ru.zeker.keymaster.domain.Algorithm;
import ru.zeker.keymaster.domain.key.KeyHeader;

public interface JwkMapper {

    Algorithm supports();

    JWK toJwk(KeyHeader key);
}
