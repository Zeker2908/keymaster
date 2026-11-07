package ru.zeker.keymaster.service;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
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

@QuarkusTest
class RoleAssignmentTest extends IntegrationTestBase {

    @Test
    void assignsRoleOnceAndWritesAuditOnlyOnFirstAssignment() {
        String userId = createUser(List.of()).jsonPath().getString("id");

        assignRole(userId, "admin")
                .then()
                .statusCode(204);

        assertEquals(1L, count("""
                SELECT count(*) AS c
                FROM keymaster.principal_role
                WHERE principal_id = $1
                """, UUID.fromString(userId)));

        assertEquals(1L, count("""
                SELECT count(*) AS c
                FROM keymaster.audit_log
                WHERE action = 'role.assigned'
                  AND target_type = 'user'
                  AND target_id = $1
                  AND details->>'role' = 'admin'
                """, userId));

        assignRole(userId, "admin")
                .then()
                .statusCode(204);

        assertEquals(1L, count("""
                SELECT count(*) AS c
                FROM keymaster.principal_role
                WHERE principal_id = $1
                """, UUID.fromString(userId)));

        assertEquals(1L, count("""
                SELECT count(*) AS c
                FROM keymaster.audit_log
                WHERE action = 'role.assigned'
                  AND target_type = 'user'
                  AND target_id = $1
                """, userId));
    }

    @Test
    void assignsRoleOnceUnderConcurrency() throws Exception {
        String userId = createUser(List.of()).jsonPath().getString("id");

        CountDownLatch start = new CountDownLatch(1);

        try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
            Future<Response> first = executor.submit(() -> {
                start.await();
                return assignRole(userId, "admin");
            });
            Future<Response> second = executor.submit(() -> {
                start.await();
                return assignRole(userId, "admin");
            });

            start.countDown();

            assertEquals(204, first.get(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS).statusCode());
            assertEquals(204, second.get(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS).statusCode());
        }

        assertEquals(1L, count("""
                SELECT count(*) AS c
                FROM keymaster.principal_role
                WHERE principal_id = $1
                """, UUID.fromString(userId)));

        assertEquals(1L, count("""
                SELECT count(*) AS c
                FROM keymaster.audit_log
                WHERE action = 'role.assigned'
                  AND target_type = 'user'
                  AND target_id = $1
                """, userId));
    }

    @Test
    void returnsUserNotFound() {
        assignRole(UUID.randomUUID().toString(), "admin")
                .then()
                .statusCode(404)
                .body("error", equalTo("USER_NOT_FOUND"));
    }

    @Test
    void returnsRoleNotFound() {
        String userId = createUser(List.of()).jsonPath().getString("id");

        assignRole(userId, "missing-role")
                .then()
                .statusCode(404)
                .body("error", equalTo("ROLE_NOT_FOUND"));

        assertEquals(0L, count("""
                SELECT count(*) AS c
                FROM keymaster.principal_role
                WHERE principal_id = $1
                """, UUID.fromString(userId)));
    }

    @Test
    void rejectsInvalidUserId() {
        assignRole("not-a-uuid", "admin")
                .then()
                .statusCode(400);
    }

    @Test
    void rejectsInvalidRoleName() {
        String userId = createUser(List.of()).jsonPath().getString("id");

        assignRole(userId, "Admin")
                .then()
                .statusCode(400);
    }

    private Response assignRole(String userId, String role) {
        return adminRequest()
                .when()
                .put("/admin/users/{id}/roles/{role}", userId, role);
    }
}
