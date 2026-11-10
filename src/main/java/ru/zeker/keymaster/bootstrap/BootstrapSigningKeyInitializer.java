package ru.zeker.keymaster.bootstrap;

import io.quarkus.runtime.StartupEvent;
import io.quarkus.vertx.VertxContextSupport;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import lombok.extern.slf4j.Slf4j;
import ru.zeker.keymaster.config.KeymasterConfig;
import ru.zeker.keymaster.service.key.SigningKeyService;

import java.time.Duration;

@Slf4j
@ApplicationScoped
public class BootstrapSigningKeyInitializer {

    private final KeymasterConfig.Bootstrap.SigningKey config;
    private final SigningKeyService keys;

    public BootstrapSigningKeyInitializer(KeymasterConfig config, SigningKeyService keys) {
        this.config = config.bootstrap().signingKey();
        this.keys = keys;
    }

    void onStart(@Observes StartupEvent event) throws Throwable {
        if (!config.enabled()) {
            log.info("Bootstrap signing key is disabled");
            return;
        }

        boolean created = VertxContextSupport.subscribeAndAwait(() -> keys.ensureInitialKey(config.algorithm())
                .ifNoItem()
                .after(Duration.ofSeconds(30))
                .fail());

        if (created) {
            log.info("Initial signing key created");
        } else {
            log.info("Signing key already present");
        }
    }
}
