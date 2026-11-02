package ru.zeker.keymaster.resource;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
class AdminResourceIntegrationTest {

    private static final Duration TIMEOUT = Duration.ofSeconds(20);
    private static final String VALID_PASSWORD = "correct-horse-1!";
    private static final String USER_ID_HEADER = "X-User-Id";
    private static final String USER_ROLES_HEADER = "X-User-Roles";

    @Inject
    Pool pool;

    private final List<UUID> createdUsers = new ArrayList<>();

    @AfterEach
    void deleteCreatedUsers() {
        createdUsers.forEach(this::deletePrincipal);
        createdUsers.clear();
    }

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
                FROM keymaster.principals
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

        Response response = adminRequest()
                .contentType(ContentType.JSON)
                .body(Map.of(
                        "login", login,
                        "password", VALID_PASSWORD
                ))
                .when()
                .post("/admin/users")
                .then()
                .statusCode(201)
                .body("roles.size()", equalTo(0))
                .extract()
                .response();

        createdUsers.add(UUID.fromString(response.jsonPath().getString("id")));
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
    void rejectsParallelDuplicateLogin() throws ExecutionException, InterruptedException {
        String login = uniqueLogin();

        CompletableFuture<Response> first = CompletableFuture.supplyAsync(() -> createUserRequest(login));
        CompletableFuture<Response> second = CompletableFuture.supplyAsync(() -> createUserRequest(login));

        List<Response> responses = List.of(first.get(), second.get());

        assertEquals(1, responses.stream().filter(r -> r.statusCode() == 201).count());
        assertEquals(1, responses.stream().filter(r -> r.statusCode() == 409).count());

        Response created = responses.stream()
                .filter(r -> r.statusCode() == 201)
                .findFirst()
                .orElseThrow();

        createdUsers.add(UUID.fromString(created.jsonPath().getString("id")));

        assertEquals(1L, count("""
            SELECT count(*) AS c
            FROM keymaster.principals
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
            FROM keymaster.principals
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
            FROM keymaster.principals
            WHERE login = $1
            """, login));
    }

    private Response createRole(String name) {
        return adminRequest()
                .contentType(ContentType.JSON)
                .body(Map.of(
                        "name", name,
                        "description", "Test role"
                ))
                .when()
                .post("/admin/admin/roles")
                .then()
                .extract()
                .response();
    }

    private List<String> existingRoleNames(int limit) {
        return pool.preparedQuery("""
            SELECT name
            FROM keymaster.roles
            ORDER BY name
            LIMIT $1
            """)
                .execute(Tuple.of(limit))
                .map(rows -> {
                    List<String> names = new ArrayList<>();
                    rows.forEach(row -> names.add(row.getString("name")));
                    return names;
                })
                .await().atMost(TIMEOUT);
    }

    private Response createUserRequest(String login) {
        return adminRequest()
                .contentType(ContentType.JSON)
                .body(Map.of(
                        "login", login,
                        "password", VALID_PASSWORD,
                        "roles", List.of()
                ))
                .when()
                .post("/admin/users");
    }

    private RequestSpecification adminRequest() {
        return adminRequest(UUID.randomUUID());
    }

    private RequestSpecification adminRequest(UUID actorId) {
        return given()
                .header(USER_ID_HEADER, actorId.toString())
                .header(USER_ROLES_HEADER, "admin");
    }

    private Response createUser(List<String> roles) {
        return createUser(uniqueLogin(), roles);
    }

    private Response createUser(String login, List<String> roles) {
        Response response = adminRequest()
                .contentType(ContentType.JSON)
                .body(Map.of(
                        "login", login,
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

    private long count(String sql, Object parameter) {
        return pool.preparedQuery(sql)
                .execute(Tuple.of(parameter))
                .map(rows -> rows.iterator().next().getLong("c"))
                .await().atMost(TIMEOUT);
    }

    private void deletePrincipal(UUID principalId) {
        pool.preparedQuery("DELETE FROM keymaster.principals WHERE id = $1")
                .execute(Tuple.of(principalId))
                .await().atMost(TIMEOUT);
    }

    private String uniqueLogin() {
        return "u-" + UUID.randomUUID().toString().substring(0, 8);
    }
}
