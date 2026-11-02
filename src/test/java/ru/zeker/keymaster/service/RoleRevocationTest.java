package ru.zeker.keymaster.service;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.vertx.mutiny.sqlclient.Pool;
import io.vertx.mutiny.sqlclient.Tuple;
import jakarta.inject.Inject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
class RoleRevocationTest {

    private static final Duration TIMEOUT = Duration.ofSeconds(20);
    private static final String VALID_PASSWORD = "correct-horse-1!";

    @Inject
    Pool pool;

    private final List<UUID> createdUsers = new ArrayList<>();

    @AfterEach
    void deleteCreatedUsers() {
        createdUsers.forEach(this::deletePrincipal);
    }

    @Test
    void revokesRoleAndWritesAudit() {
        String userId = createUser(List.of("admin")).jsonPath().getString("id");
        createUser(List.of("admin"));

        revokeRole(userId, "admin")
                .then()
                .statusCode(204);

        assertEquals(0L, count("""
                SELECT count(*) AS c
                FROM keymaster.principal_roles
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
        List<UUID> previousAdmins = adminAssignments();
        String userId = createUser(List.of("admin")).jsonPath().getString("id");
        UUID targetId = UUID.fromString(userId);

        try {
            pool.preparedQuery("""
                            DELETE FROM keymaster.principal_roles pr
                            USING keymaster.roles r
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
                    FROM keymaster.principal_roles
                    WHERE principal_id = $1
                    """, targetId));

            assertEquals(0L, count("""
                    SELECT count(*) AS c
                    FROM keymaster.audit_log
                    WHERE action = 'role.revoked'
                      AND target_id = $1
                    """, userId));
        } finally {
            deletePrincipal(targetId);
            restoreAdminAssignments(previousAdmins);
        }
    }

    @Test
    void preventsConcurrentRevocationOfLastAdmins() throws Exception {
        List<UUID> previousAdmins = adminAssignments();

        try {
            String firstUserId = createUser(List.of("admin")).jsonPath().getString("id");
            String secondUserId = createUser(List.of("admin")).jsonPath().getString("id");

            UUID firstId = UUID.fromString(firstUserId);
            UUID secondId = UUID.fromString(secondUserId);

            pool.preparedQuery("""
                        DELETE FROM keymaster.principal_roles pr
                        USING keymaster.roles r
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

            List<UUID> remainingAdmins = adminAssignments();

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

        } finally {
            restoreAdminAssignments(previousAdmins);
        }
    }

    private Response createUser(List<String> roles) {
        Response response = given()
                .contentType(ContentType.JSON)
                .header("X-User-Id", UUID.randomUUID().toString())
                .header("X-User-Roles", "admin")
                .body(Map.of(
                        "login", uniqueLogin(),
                        "password", VALID_PASSWORD,
                        "roles", roles
                ))
                .when()
                .post("/admin/users")
                .then()
                .statusCode(201)
                .extract()
                .response();
        createdUsers.add(UUID.fromString(response.jsonPath().getString("id")));
        return response;
    }

    private Response revokeRole(String userId, String role) {
        return given()
                .header("X-User-Id", UUID.randomUUID().toString())
                .header("X-User-Roles", "admin")
                .when()
                .delete("/admin/users/{id}/roles/{role}", userId, role);
    }

    private List<UUID> adminAssignments() {
        return pool.preparedQuery("""
                        SELECT pr.principal_id
                        FROM keymaster.principal_roles pr
                        JOIN keymaster.roles r ON r.id = pr.role_id
                        WHERE r.name = 'admin'
                        """)
                .execute()
                .map(rows -> {
                    List<UUID> ids = new ArrayList<>();
                    rows.forEach(row -> ids.add(row.getUUID("principal_id")));
                    return ids;
                })
                .await().atMost(TIMEOUT);
    }

    private void restoreAdminAssignments(List<UUID> principalIds) {
        pool.preparedQuery("""
                        DELETE FROM keymaster.principal_roles pr
                        USING keymaster.roles r
                        WHERE pr.role_id = r.id
                          AND r.name = 'admin'
                        """)
                .execute()
                .await().atMost(TIMEOUT);

        for (UUID principalId : principalIds) {
            pool.preparedQuery("""
                            INSERT INTO keymaster.principal_roles (principal_id, role_id)
                            SELECT $1, r.id
                            FROM keymaster.roles r
                            WHERE r.name = 'admin'
                            ON CONFLICT DO NOTHING
                            """)
                    .execute(Tuple.of(principalId))
                    .await().atMost(TIMEOUT);
        }
    }

    private void deletePrincipal(UUID principalId) {
        pool.preparedQuery("DELETE FROM keymaster.principals WHERE id = $1")
                .execute(Tuple.of(principalId))
                .await().atMost(TIMEOUT);
    }

    private long count(String sql, Object parameter) {
        return pool.preparedQuery(sql)
                .execute(Tuple.of(parameter))
                .map(rows -> rows.iterator().next().getLong("c"))
                .await().atMost(TIMEOUT);
    }

    private String uniqueLogin() {
        return "u-" + UUID.randomUUID().toString().substring(0, 8);
    }
}
