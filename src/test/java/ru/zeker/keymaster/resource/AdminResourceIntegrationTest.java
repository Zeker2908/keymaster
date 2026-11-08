package ru.zeker.keymaster.resource;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import org.junit.jupiter.api.Test;
import ru.zeker.keymaster.IntegrationTestBase;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
class AdminResourceIntegrationTest extends IntegrationTestBase {

    @Test
    void requiresUserIdHeader() {
        given()
                .header(USER_ROLES_HEADER, "admin")
                .when()
                .get("/admin/users/{id}", UUID.randomUUID())
                .then()
                .statusCode(401)
                .body("error", equalTo("UNAUTHORIZED"));
    }

    @Test
    void requiresRolesHeader() {
        given()
                .header(USER_ID_HEADER, UUID.randomUUID().toString())
                .when()
                .get("/admin/users/{id}", UUID.randomUUID())
                .then()
                .statusCode(401)
                .body("error", equalTo("UNAUTHORIZED"));
    }

    @Test
    void forbidsNonAdmin() {
        given()
                .header(USER_ID_HEADER, UUID.randomUUID().toString())
                .header(USER_ROLES_HEADER, "viewer")
                .when()
                .get("/admin/users/{id}", UUID.randomUUID())
                .then()
                .statusCode(403)
                .body("error", equalTo("FORBIDDEN"));
    }

    @Test
    void forbidsNonAdminOnCreateWithoutInsertingUser() {
        String login = uniqueLogin();

        given()
                .contentType(ContentType.JSON)
                .header(USER_ID_HEADER, UUID.randomUUID().toString())
                .header(USER_ROLES_HEADER, "viewer")
                .body(Map.of(
                        "login", login,
                        "password", VALID_PASSWORD,
                        "roles", List.of("admin")
                ))
                .when()
                .post("/admin/users")
                .then()
                .statusCode(403)
                .body("error", equalTo("FORBIDDEN"));

        assertEquals(0L, count("""
                SELECT count(*) AS c
                FROM keymaster.principal
                WHERE login = $1
                """, login));
    }

    @Test
    void acceptsAdminAmongMultipleRoles() {
        given()
                .header(USER_ID_HEADER, UUID.randomUUID().toString())
                .header(USER_ROLES_HEADER, "viewer, admin")
                .when()
                .get("/admin/users/{id}", UUID.randomUUID())
                .then()
                .statusCode(404)
                .body("error", equalTo("USER_NOT_FOUND"));
    }

    @Test
    void createsUser() {
        String login = uniqueLogin();

        Response response = createUser(login, List.of("admin"));
        String userId = response.jsonPath().getString("id");

        assertNotNull(userId);
        assertEquals(login, response.jsonPath().getString("login"));
        assertEquals("USER", response.jsonPath().getString("kind"));
        assertEquals("ACTIVE", response.jsonPath().getString("status"));
        assertEquals(1, response.jsonPath().getList("roles").size());
        assertEquals("admin", response.jsonPath().getString("roles[0].name"));
        assertNotNull(response.jsonPath().getString("createdAt"));

        String location = response.header("Location");
        assertNotNull(location);
        assertTrue(location.endsWith("/admin/users/" + userId));

        assertEquals(1L, count("""
                SELECT count(*) AS c
                FROM keymaster.audit_log
                WHERE action = 'user.created'
                  AND target_type = 'user'
                  AND target_id = $1
                """, userId));
    }

    @Test
    void createsUserWithoutRoles() {
        String login = uniqueLogin();

        postUser(Map.of(
                        "login", login,
                        "password", VALID_PASSWORD
                ))
                .then()
                .statusCode(201)
                .body("roles.size()", equalTo(0));
    }

    @Test
    void rejectsInvalidCreateRequest() {
        adminRequest()
                .contentType(ContentType.JSON)
                .body(Map.of(
                        "login", "A",
                        "password", VALID_PASSWORD,
                        "roles", List.of("admin")
                ))
                .when()
                .post("/admin/users")
                .then()
                .statusCode(400)
                .body("status", equalTo(400));
    }

    @Test
    void returnsNotFoundForUnknownUserOnGet() {
        String userId = UUID.randomUUID().toString();

        adminRequest()
                .when()
                .get("/admin/users/{id}", userId)
                .then()
                .statusCode(404)
                .body("error", equalTo("USER_NOT_FOUND"));

        assertEquals(0L, count("""
                SELECT count(*) AS c
                FROM keymaster.audit_log
                WHERE action = 'user.searched'
                  AND target_id = $1
                """, userId));
    }

    @Test
    void rejectsInvalidUserIdOnGet() {
        adminRequest()
                .when()
                .get("/admin/users/not-a-uuid")
                .then()
                .statusCode(400)
                .body("status", equalTo(400));
    }

    @Test
    void assignsRoleIdempotently() {
        String userId = createUser(List.of()).jsonPath().getString("id");

        adminRequest()
                .when()
                .put("/admin/users/{id}/roles/{role}", userId, "admin")
                .then()
                .statusCode(204);

        adminRequest()
                .when()
                .put("/admin/users/{id}/roles/{role}", userId, "admin")
                .then()
                .statusCode(204);

        adminRequest()
                .when()
                .get("/admin/users/{id}", userId)
                .then()
                .statusCode(200)
                .body("roles.size()", equalTo(1))
                .body("roles[0].name", equalTo("admin"));

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
    }

    @Test
    void revokesRoleIdempotently() {
        String userId = createUser(List.of("admin")).jsonPath().getString("id");
        createUser(List.of("admin"));

        adminRequest()
                .when()
                .delete("/admin/users/{id}/roles/{role}", userId, "admin")
                .then()
                .statusCode(204);

        adminRequest()
                .when()
                .delete("/admin/users/{id}/roles/{role}", userId, "admin")
                .then()
                .statusCode(204);

        adminRequest()
                .when()
                .get("/admin/users/{id}", userId)
                .then()
                .statusCode(200)
                .body("roles.size()", equalTo(0));

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
    void returnsNotFoundForUnknownUserOnRoleMutations() {
        String userId = UUID.randomUUID().toString();

        adminRequest()
                .when()
                .put("/admin/users/{id}/roles/{role}", userId, "admin")
                .then()
                .statusCode(404)
                .body("error", equalTo("USER_NOT_FOUND"));

        adminRequest()
                .when()
                .delete("/admin/users/{id}/roles/{role}", userId, "admin")
                .then()
                .statusCode(404)
                .body("error", equalTo("USER_NOT_FOUND"));
    }

    @Test
    void returnsNotFoundForUnknownRoleOnRoleMutations() {
        String userId = createUser(List.of()).jsonPath().getString("id");

        adminRequest()
                .when()
                .put("/admin/users/{id}/roles/{role}", userId, "missing-role")
                .then()
                .statusCode(404)
                .body("error", equalTo("ROLE_NOT_FOUND"));

        adminRequest()
                .when()
                .delete("/admin/users/{id}/roles/{role}", userId, "missing-role")
                .then()
                .statusCode(404)
                .body("error", equalTo("ROLE_NOT_FOUND"));
    }

    @Test
    void rejectsInvalidRoleNameOnRoleMutations() {
        String userId = createUser(List.of()).jsonPath().getString("id");

        adminRequest()
                .when()
                .put("/admin/users/{id}/roles/{role}", userId, "Admin")
                .then()
                .statusCode(400)
                .body("status", equalTo(400));

        adminRequest()
                .when()
                .delete("/admin/users/{id}/roles/{role}", userId, "Admin")
                .then()
                .statusCode(400)
                .body("status", equalTo(400));
    }

    @Test
    void rejectsInvalidUserIdOnRoleMutations() {
        adminRequest()
                .when()
                .put("/admin/users/not-a-uuid/roles/admin")
                .then()
                .statusCode(400)
                .body("status", equalTo(400));

        adminRequest()
                .when()
                .delete("/admin/users/not-a-uuid/roles/admin")
                .then()
                .statusCode(400)
                .body("status", equalTo(400));
    }

    @Test
    void rejectsDuplicateLoginWithoutExposingDatabaseError() {
        String login = uniqueLogin();

        createUser(login, List.of());

        adminRequest()
                .contentType(ContentType.JSON)
                .body(Map.of(
                        "login", login,
                        "password", VALID_PASSWORD,
                        "roles", List.of()
                ))
                .when()
                .post("/admin/users")
                .then()
                .statusCode(409)
                .body("error", equalTo("LOGIN_ALREADY_EXISTS"))
                .body("message", notNullValue())
                .body("message", org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("unique constraint")));
    }

    @Test
    void mapsDuplicateRoleNameToConflict() {
        String roleName = "test-" + UUID.randomUUID().toString().substring(0, 8);

        assertEquals(201, createRole(roleName).statusCode());

        createRole(roleName)
                .then()
                .statusCode(409)
                .body("error", equalTo("ROLE_ALREADY_EXISTS"))
                .body("message", equalTo("Role already exists"));
    }

    @Test
    void rejectsParallelDuplicateLogin() throws ExecutionException, InterruptedException {
        String login = uniqueLogin();

        CompletableFuture<Response> first = CompletableFuture.supplyAsync(() -> postUser(login, List.of()));
        CompletableFuture<Response> second = CompletableFuture.supplyAsync(() -> postUser(login, List.of()));

        List<Response> responses = List.of(first.get(), second.get());

        assertEquals(1, responses.stream().filter(r -> r.statusCode() == 201).count());
        assertEquals(1, responses.stream().filter(r -> r.statusCode() == 409).count());

        assertEquals(1L, count("""
            SELECT count(*) AS c
            FROM keymaster.principal
            WHERE login = $1
            """, login));
    }

    @Test
    void rollsBackUserCreationWhenRoleIsUnknown() {
        String login = uniqueLogin();

        adminRequest()
                .contentType(ContentType.JSON)
                .body(Map.of(
                        "login", login,
                        "password", VALID_PASSWORD,
                        "roles", List.of("unknown-role-" + UUID.randomUUID())
                ))
                .when()
                .post("/admin/users")
                .then()
                .statusCode(400)
                .body("error", equalTo("UNKNOWN_ROLE"));

        assertEquals(0L, count("""
            SELECT count(*) AS c
            FROM keymaster.principal
            WHERE login = $1
            """, login));
    }

    @Test
    void createsUserAndAuditsUserCreationAndEveryRoleAssignment() {
        String roleName = "test-" + UUID.randomUUID().toString().substring(0, 8);

        Response roleResponse = createRole(roleName);

        assertEquals(201, roleResponse.statusCode(), roleResponse.asString());

        Response response = createUser(uniqueLogin(), List.of("admin", roleName));
        UUID userId = UUID.fromString(response.jsonPath().getString("id"));

        assertEquals(2, response.jsonPath().getList("roles").size());

        assertEquals(3L, count("""
            SELECT count(*) AS c
            FROM keymaster.audit_log
            WHERE target_id = $1
              AND target_type = 'user'
              AND action IN ('user.created', 'role.assigned')
            """, userId.toString()));
    }

    @Test
    void rejectsPasswordViolatingPolicyWithoutEchoingPassword() {
        String login = uniqueLogin();
        String invalidPassword = "short";

        adminRequest()
                .contentType(ContentType.JSON)
                .body(Map.of(
                        "login", login,
                        "password", invalidPassword,
                        "roles", List.of()
                ))
                .when()
                .post("/admin/users")
                .then()
                .statusCode(400)
                .body("error", equalTo("PASSWORD_POLICY_VIOLATION"))
                .body(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString(invalidPassword)));

        assertEquals(0L, count("""
            SELECT count(*) AS c
            FROM keymaster.principal
            WHERE login = $1
            """, login));
    }
}
