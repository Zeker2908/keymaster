package ru.zeker.keymaster.service;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.vertx.mutiny.sqlclient.Pool;
import io.vertx.mutiny.sqlclient.Tuple;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;

@QuarkusTest
class RoleAssignmentTest {

    private static final Duration TIMEOUT = Duration.ofSeconds(20);
    private static final String VALID_PASSWORD = "correct-horse-1!";

    @Inject
    Pool pool;

    @Test
    void assignsRoleOnceAndWritesAuditOnlyOnFirstAssignment() {
        String userId = createUser(List.of()).jsonPath().getString("id");

        assignRole(userId, "admin")
                .then()
                .statusCode(204);

        assertEquals(1L, count("""
                SELECT count(*) AS c
                FROM keymaster.principal_roles
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
                FROM keymaster.principal_roles
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
                FROM keymaster.principal_roles
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

    private Response createUser(List<String> roles) {
        return given()
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
    }

    private Response assignRole(String userId, String role) {
        return given()
                .header("X-User-Id", UUID.randomUUID().toString())
                .header("X-User-Roles", "admin")
                .when()
                .put("/admin/users/{id}/roles/{role}", userId, role);
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
