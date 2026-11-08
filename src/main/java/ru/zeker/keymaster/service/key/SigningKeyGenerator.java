package ru.zeker.keymaster.service.key;

import io.smallrye.mutiny.Uni;
import io.vertx.core.Context;
import io.vertx.core.Vertx;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Named;
import ru.zeker.keymaster.domain.key.GeneratedKey;
import ru.zeker.keymaster.domain.key.RsaKeyCodec;
import ru.zeker.keymaster.exception.ServiceOverloadedException;
import ru.zeker.keymaster.util.Secrets;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;

@ApplicationScoped
public final class SigningKeyGenerator {

    private static final String ALGORITHM = "RSA";
    private static final int KEY_SIZE = 2048;

    private final ExecutorService executor;

    public SigningKeyGenerator(@Named("key-generation") ExecutorService executor) {
        this.executor = executor;
    }

    public Uni<GeneratedKey> generate() {
        Context context = Vertx.currentContext();

        return Uni.createFrom()
                .item(this::generateKey)
                .runSubscriptionOn(executor)
                .onFailure(RejectedExecutionException.class)
                .transform(ServiceOverloadedException::new)
                .emitOn(context == null
                        ? Runnable::run
                        : command -> context.runOnContext(_ -> command.run())
                );
    }

    private GeneratedKey generateKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
            generator.initialize(KEY_SIZE);

            KeyPair keyPair = generator.generateKeyPair();

            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

            String kid = RsaKeyCodec.thumbprint(publicKey);

            byte[] publicSpki = RsaKeyCodec.toSpki(publicKey);
            byte[] privatePkcs8 = RsaKeyCodec.toPkcs8(keyPair.getPrivate());

            try {
                return new GeneratedKey(kid, publicSpki, privatePkcs8);
            } finally {
                Secrets.wipe(privatePkcs8);
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("RSA key generation failed", e);
        }
    }
}
