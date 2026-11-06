package ru.zeker.keymaster.service.key;

import io.quarkus.hibernate.reactive.panache.Panache;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.vertx.RunOnVertxContext;
import io.quarkus.test.vertx.UniAsserter;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import ru.zeker.keymaster.domain.key.RsaKeyCodec;
import ru.zeker.keymaster.repository.PrincipalRepository;

import java.security.interfaces.RSAPublicKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
class SigningKeyGeneratorIntegrationTest {

    @Inject
    SigningKeyGenerator generator;

    @Inject
    PrincipalRepository principals;

    @Test
    @RunOnVertxContext
    void reactiveSessionWorksAfterGeneration(UniAsserter asserter) {
        asserter.assertThat(
                () -> generator.generate()
                        .invoke(key -> {
                            assertNotNull(key);
                            RSAPublicKey publicKey = (RSAPublicKey) RsaKeyCodec.publicFromSpki(key.publicSpki());
                            assertEquals(RsaKeyCodec.thumbprint(publicKey), key.kid());
                            assertNotNull(RsaKeyCodec.privateFromPkcs8(key.privatePkcs8()));
                        })
                        .chain(key -> Panache.withSession(principals::count)),
                count -> assertTrue(count >= 0)
        );
    }
}
