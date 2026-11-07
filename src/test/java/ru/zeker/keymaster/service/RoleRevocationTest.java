package ru.zeker.keymaster.service;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import io.vertx.mutiny.sqlclient.Tuple;
import org.junit.jupiter.api.Test;
import ru.zeker.keymaster.IntegrationTestBase;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
class RoleRevocationTest extends IntegrationTestBase {

    @Test
    void revokesRoleAndWritesAudit() {
        String userId = createUser(List.of("admin")).jsonPath().getString("id");
        createUser(List.of("admin"));

        revokeRole(userId, "admin")
                .then()
                .statusCode(204);

        assertEquals(0L, count("""
                SELECT count(*) AS c
                FROM keymaster.principal_role
                WHERE principal_id = $1
                """, UUID.fromString(userId)));

        assertEquals(1L, count("""
                SELECT count(*) AS c
                FROM keymaster.audit_log
                WHERE action = 'role.revoked'
                  AND target_type = 'user'
                  AND target_id = $1
                  AND details->>'role' = 'admin'
                """, userId));
    }

    @Test
    void doesNothingWhenRoleIsNotAssigned() {
        String userId = createUser(List.of()).jsonPath().getString("id");

        revokeRole(userId, "admin")
                .then()
                .statusCode(204);

        assertEquals(0L, count("""
                SELECT count(*) AS c
                FROM keymaster.audit_log
                WHERE action = 'role.revoked'
                  AND target_id = $1
                """, userId));
    }

    @Test
    void returnsUserNotFound() {
        revokeRole(UUID.randomUUID().toString(), "admin")
                .then()
                .statusCode(404)
                .body("error", equalTo("USER_NOT_FOUND"));
    }

    @Test
    void returnsRoleNotFound() {
        String userId = createUser(List.of()).jsonPath().getString("id");

        revokeRole(userId, "missing-role")
                .then()
                .statusCode(404)
                .body("error", equalTo("ROLE_NOT_FOUND"));
    }

    @Test
    void rejectsInvalidUserId() {
        revokeRole("not-a-uuid", "admin")
                .then()
                .statusCode(400);
    }

    @Test
    void rejectsInvalidRoleName() {
        String userId = createUser(List.of()).jsonPath().getString("id");

        revokeRole(userId, "Admin")
                .then()
                .statusCode(400);
    }

    @Test
    void refusesToRevokeLastActiveAdmin() {
        String userId = createUser(List.of("admin")).jsonPath().getString("id");
        UUID targetId = UUID.fromString(userId);

        // вычищаем остальных админов, чтобы целевой стал последним;
        // состояние назначений и созданных пользователей восстановит IntegrationTestBase
        pool.preparedQuery("""
                        DELETE FROM keymaster.principal_role pr
                        USING keymaster.role r
                        WHERE pr.role_id = r.id
                          AND r.name = 'admin'
                          AND pr.principal_id <> $1
                        """)
                .execute(Tuple.of(targetId))
                .await().atMost(TIMEOUT);

        revokeRole(userId, "admin")
                .then()
                .statusCode(409)
                .body("error", equalTo("LAST_ADMIN"));

        assertEquals(1L, count("""
                SELECT count(*) AS c
                FROM keymaster.principal_role
                WHERE principal_id = $1
                """, targetId));

        assertEquals(0L, count("""
                SELECT count(*) AS c
                FROM keymaster.audit_log
                WHERE action = 'role.revoked'
                  AND target_id = $1
                """, userId));
    }

    @Test
    void preventsConcurrentRevocationOfLastAdmins() throws Exception {
        String firstUserId = createUser(List.of("admin")).jsonPath().getString("id");
        String secondUserId = createUser(List.of("admin")).jsonPath().getString("id");

        UUID firstId = UUID.fromString(firstUserId);
        UUID secondId = UUID.fromString(secondUserId);

        // оставляем админами только двух участников теста
        pool.preparedQuery("""
                    DELETE FROM keymaster.principal_role pr
                    USING keymaster.role r
                    WHERE pr.role_id = r.id
                      AND r.name = 'admin'
                      AND pr.principal_id NOT IN ($1, $2)
                    """)
                .execute(Tuple.of(firstId, secondId))
                .await().atMost(TIMEOUT);

        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);

        try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
            Future<Response> first = executor.submit(() -> {
                ready.countDown();
                start.await();
                return revokeRole(firstUserId, "admin");
            });

            Future<Response> second = executor.submit(() -> {
                ready.countDown();
                start.await();
                return revokeRole(secondUserId, "admin");
            });

            assertTrue(ready.await(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS));
            start.countDown();

            Response firstResponse = first.get(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
            Response secondResponse = second.get(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);

            List<Integer> statuses = List.of(
                    firstResponse.statusCode(),
                    secondResponse.statusCode()
            );

            assertEquals(1, statuses.stream().filter(status -> status == 204).count());
            assertEquals(1, statuses.stream().filter(status -> status == 409).count());

            Response conflict = firstResponse.statusCode() == 409
                    ? firstResponse
                    : secondResponse;

            assertEquals("LAST_ADMIN", conflict.jsonPath().getString("error"));
        }

        List<UUID> remainingAdmins = principalsWithAdminRole();

        assertEquals(1, remainingAdmins.size());
        assertTrue(remainingAdmins.contains(firstId) || remainingAdmins.contains(secondId));

        long firstAudit = count("""
            SELECT count(*) AS c
            FROM keymaster.audit_log
            WHERE action = 'role.revoked'
              AND target_id = $1
            """, firstUserId);

        long secondAudit = count("""
            SELECT count(*) AS c
            FROM keymaster.audit_log
            WHERE action = 'role.revoked'
              AND target_id = $1
            """, secondUserId);

        assertEquals(1L, firstAudit + secondAudit);
    }

    private Response revokeRole(String userId, String role) {
        return adminRequest()
                .when()
                .delete("/admin/users/{id}/roles/{role}", userId, role);
    }
}
