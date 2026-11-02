package ru.zeker.keymaster.bootstrap;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.quarkus.vertx.VertxContextSupport;
import io.vertx.mutiny.sqlclient.Pool;
import io.vertx.mutiny.sqlclient.Tuple;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import ru.zeker.keymaster.service.BootstrapAdminService;

import java.time.Duration;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@QuarkusTest
@TestProfile(BootstrapAdminTestProfile.class)
class BootstrapAdminInitializerTest {

    private static final Duration TIMEOUT = Duration.ofSeconds(20);
    private static final String LOGIN = "bootstrap-admin";

    @Inject
    Pool pool;

    @Inject
    BootstrapAdminService service;

    @Test
    void createsAdminOnStartup() {
        UUID userId = userId();

        assertNotNull(userId);

        assertEquals(1L, count("""
                SELECT count(*) AS c
                FROM keymaster.principals p
                JOIN keymaster.principal_roles pr ON pr.principal_id = p.id
                JOIN keymaster.roles r ON r.id = pr.role_id
                WHERE p.id = $1
                  AND p.status = 'ACTIVE'
                  AND r.name = 'admin'
                """, userId));

        assertEquals(2L, bootstrapAuditCount(userId));
    }

    @Test
    void doesNotChangePasswordOrDuplicateAuditWhenAdminAlreadyExists() throws Throwable {
        UUID userId = userId();
        String hashBefore = secretHash(userId);
        long auditCountBefore = bootstrapAuditCount(userId);

        boolean created = VertxContextSupport.subscribeAndAwait(() ->
                service.ensureAdmin(LOGIN, "AnotherStrongPassword123!")
                        .ifNoItem()
                        .after(TIMEOUT)
                        .fail());

        assertFalse(created);
        assertEquals(hashBefore, secretHash(userId));
        assertEquals(auditCountBefore, bootstrapAuditCount(userId));
    }

    private UUID userId() {
        return pool.preparedQuery("""
                        SELECT id
                        FROM keymaster.principals
                        WHERE login = $1
                        """)
                .execute(Tuple.of(LOGIN))
                .map(rows -> rows.iterator().hasNext()
                        ? rows.iterator().next().getUUID("id")
                        : null)
                .await().atMost(TIMEOUT);
    }

    private String secretHash(UUID userId) {
        return pool.preparedQuery("""
                        SELECT secret_hash
                        FROM keymaster.credentials
                        WHERE principal_id = $1
                        """)
                .execute(Tuple.of(userId))
                .map(rows -> rows.iterator().next().getString("secret_hash"))
                .await().atMost(TIMEOUT);
    }

    private long bootstrapAuditCount(UUID userId) {
        return count("""
                SELECT count(*) AS c
                FROM keymaster.audit_log
                WHERE target_type = 'user'
                  AND target_id = $1
                  AND action IN ('user.created', 'role.assigned')
                  AND actor_id IS NULL
                  AND request_id = 'bootstrap'
                """, userId.toString());
    }

    private long count(String sql, Object parameter) {
        return pool.preparedQuery(sql)
                .execute(Tuple.of(parameter))
                .map(rows -> rows.iterator().next().getLong("c"))
                .await().atMost(TIMEOUT);
    }
}
