package ru.zeker.keymaster.bootstrap;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.quarkus.vertx.VertxContextSupport;
import jakarta.inject.Inject;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import ru.zeker.keymaster.IntegrationTestBase;
import ru.zeker.keymaster.service.key.SigningKeyService;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@TestProfile(BootstrapSigningKeyTestProfile.class)
class BootstrapSigningKeyInitializerTest extends IntegrationTestBase {

    private static final int PARALLEL_CALLS = 5;

    @Inject
    SigningKeyService keys;

    @Inject
    Flyway flyway;

    @Test
    void createsInitialKeyAfterMigrationsOnStartup() {
        assertNotNull(flyway.info().current(), "Flyway migrations must be applied before key initialization");
        assertEquals(1L, count("SELECT count(*) AS c FROM keymaster.signing_key"));

        String kid = singleKeyKid();
        assertEquals(1L, keyCreatedAuditCount(kid));
    }

    @Test
    void doesNotCreateAnotherKeyWhenOneExists() throws Throwable {
        String kidBefore = singleKeyKid();
        String createdAtBefore = singleKeyCreatedAt();

        boolean created = VertxContextSupport.subscribeAndAwait(() ->
                keys.ensureInitialKey()
                        .ifNoItem()
                        .after(TIMEOUT)
                        .fail());

        assertFalse(created);
        assertEquals(1L, count("SELECT count(*) AS c FROM keymaster.signing_key"));
        assertEquals(kidBefore, singleKeyKid());
        assertEquals(createdAtBefore, singleKeyCreatedAt());
        assertEquals(1L, keyCreatedAuditCount(kidBefore));
    }

    @Test
    void parallelEnsureInitialKeyLeavesSingleKeyWithoutErrors() throws Exception {
        pool.query("DELETE FROM keymaster.signing_key").execute().await().atMost(TIMEOUT);

        ExecutorService executor = Executors.newFixedThreadPool(PARALLEL_CALLS);
        CountDownLatch start = new CountDownLatch(1);

        try {
            List<Future<Boolean>> results = new ArrayList<>(PARALLEL_CALLS);
            for (int i = 0; i < PARALLEL_CALLS; i++) {
                results.add(executor.submit(() -> {
                    start.await();
                    try {
                        return VertxContextSupport.subscribeAndAwait(() ->
                                keys.ensureInitialKey()
                                        .ifNoItem()
                                        .after(Duration.ofSeconds(60))
                                        .fail());
                    } catch (Throwable failure) {
                        throw new IllegalStateException(failure);
                    }
                }));
            }

            start.countDown();

            int createdCount = 0;
            for (Future<Boolean> result : results) {
                if (result.get(90, TimeUnit.SECONDS)) {
                    createdCount++;
                }
            }

            assertEquals(1, createdCount, "exactly one parallel call must create the key");
            assertEquals(1L, count("SELECT count(*) AS c FROM keymaster.signing_key"));
            assertTrue(keyCreatedAuditCount(singleKeyKid()) >= 1);
        } finally {
            executor.shutdownNow();
        }
    }

    private String singleKeyKid() {
        return pool.query("SELECT kid FROM keymaster.signing_key")
                .execute()
                .map(rows -> rows.iterator().next().getString("kid"))
                .await().atMost(TIMEOUT);
    }

    private String singleKeyCreatedAt() {
        return pool.query("SELECT created_at::text AS created_at FROM keymaster.signing_key")
                .execute()
                .map(rows -> rows.iterator().next().getString("created_at"))
                .await().atMost(TIMEOUT);
    }

    private long keyCreatedAuditCount(String kid) {
        return count("""
                SELECT count(*) AS c
                FROM keymaster.audit_log
                WHERE target_type = 'signingKey'
                  AND action = 'key.created'
                  AND target_id = $1
                """, kid);
    }
}
