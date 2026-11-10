package ru.zeker.keymaster.mapper.jwk;

import com.nimbusds.jose.jwk.Curve;
import jakarta.enterprise.context.ApplicationScoped;
import ru.zeker.keymaster.domain.Algorithm;

@ApplicationScoped
public class Es384JwkMapper extends EcJwkMapper {

    @Override
    public Algorithm supports() {
        return Algorithm.ES384;
    }

    @Override
    protected Curve curve() {
        return Curve.P_384;
    }
}
