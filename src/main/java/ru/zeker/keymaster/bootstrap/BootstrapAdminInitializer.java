package ru.zeker.keymaster.bootstrap;

import io.quarkus.runtime.StartupEvent;
import io.quarkus.vertx.VertxContextSupport;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import ru.zeker.keymaster.config.KeymasterConfig;
import ru.zeker.keymaster.service.BootstrapAdminService;

import java.time.Duration;

@Slf4j
@ApplicationScoped
public class BootstrapAdminInitializer {

    private final KeymasterConfig.Bootstrap.Admin config;
    private final BootstrapAdminService service;

    public BootstrapAdminInitializer(KeymasterConfig config, BootstrapAdminService service) {
        this.config = config.bootstrap().admin();
        this.service = service;
    }

    void onStart(@Observes StartupEvent event) throws Throwable {
        if (!config.enabled()) {
            log.info("Bootstrap admin is disabled");
            return;
        }

        String login = config.login()
                .filter(StringUtils::isNotBlank)
                .orElseThrow(() -> new IllegalStateException("Bootstrap admin login is not configured"));

        String password = config.password()
                .filter(StringUtils::isNotBlank)
                .orElseThrow(() -> new IllegalStateException("Bootstrap admin password is not configured"));

        boolean created = VertxContextSupport.subscribeAndAwait(() -> service.ensureAdmin(login, password)
                .ifNoItem()
                .after(Duration.ofSeconds(30))
                .fail());

        if (created) {
            log.info("Bootstrap admin '{}' created", login);
        } else {
            log.info("Bootstrap admin '{}' already present", login);
        }
    }

}
