package ru.zeker.keymaster.service.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.enterprise.context.ApplicationScoped;
import ru.zeker.keymaster.config.JwtConfig;
import ru.zeker.keymaster.config.KeysConfig;
import ru.zeker.keymaster.domain.jwt.Subject;
import ru.zeker.keymaster.domain.key.SigningKeyData;
import ru.zeker.keymaster.exception.ErrorCode;
import ru.zeker.keymaster.exception.KeyMasterException;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@ApplicationScoped
public class AccessTokenFactory {

    private static final String ROLES = "roles";

    private final String audience;
    private final String issuer;
    private final Duration ttl;

    public AccessTokenFactory(JwtConfig jwt, KeysConfig keys) {
        this.audience = jwt.audience();
        this.issuer = jwt.issuer();
        this.ttl = keys.maxAccessTtl();
    }

    public Duration ttl() {
        return ttl;
    }

    public JWT issue(SigningKeyData key, Subject subject, Instant now) {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(subject.userId().toString())
                .claim(ROLES, subject.roles())
                .audience(audience)
                .issuer(issuer)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(ttl)))
                .jwtID(UUID.randomUUID().toString())
                .build();

        JWSHeader header = new JWSHeader.Builder(key.algorithm().getJwsAlgorithm())
                .keyID(key.kid())
                .type(JOSEObjectType.JWT)
                .build();

        SignedJWT jwt = new SignedJWT(header, claims);

        try {
            jwt.sign(key.algorithm().createSigner(key.privateKey()));
            return jwt;
        } catch (JOSEException e) {
            throw new KeyMasterException(ErrorCode.SIGNING_UNAVAILABLE, e);
        }
    }
}
