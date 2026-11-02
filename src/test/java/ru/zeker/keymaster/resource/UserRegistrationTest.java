package ru.zeker.keymaster.resource;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.vertx.mutiny.sqlclient.Pool;
import io.vertx.mutiny.sqlclient.Tuple;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;

@QuarkusTest
class UserRegistrationTest {

    private static final Duration TIMEOUT = Duration.ofSeconds(20);
    private static final String VALID_PASSWORD = "correct-horse-1!";

    @Inject
    Pool pool;

    @Test
    void createsUserWithRoles() {
        String login = uniqueLogin();

        given()
                .contentType(ContentType.JSON)
                .header("X-User-Id", UUID.randomUUID().toString())
                .header("X-User-Roles", "admin")
                .body(Map.of(
                        "login", login,
                        "password", VALID_PASSWORD,
                        "roles", List.of("admin")
                ))
                .when()
                .post("/admin/users")
                .then()
                .statusCode(201)
                .body("login", equalTo(login))
                .body("kind", equalTo("USER"))
                .body("status", equalTo("ACTIVE"))
                .body("roles.size()", equalTo(1))
                .body("roles[0].name", equalTo("admin"))
                .body("createdAt", notNullValue());
    }

    @Test
    void mapsDuplicateLoginToConflict() {
        String login = uniqueLogin();

        createUser(login)
                .then()
                .statusCode(201);

        createUser(login)
                .then()
                .statusCode(409)
                .body("error", equalTo("LOGIN_ALREADY_EXISTS"))
                .body("message", equalTo("Login already exists"));
    }

    @Test
    void rejectsUnknownRoleWithoutInsertingPrincipal() {
        String login = uniqueLogin();

        given()
                .contentType(ContentType.JSON)
                .header("X-User-Id", UUID.randomUUID().toString())
                .header("X-User-Roles", "admin")
                .body(Map.of(
                        "login", login,
                        "password", VALID_PASSWORD,
                        "roles", List.of("missing-role")
                ))
                .when()
                .post("/admin/users")
                .then()
                .statusCode(400)
                .body("error", equalTo("UNKNOWN_ROLE"));

        Long count = pool.preparedQuery("""
                        SELECT count(*) AS c
                        FROM keymaster.principals
                        WHERE login = $1
                        """)
                .execute(Tuple.of(login))
                .map(rows -> rows.iterator().next().getLong("c"))
                .await().atMost(TIMEOUT);

        assertEquals(0L, count);
    }

    @Test
    void writesUserCreatedBeforeRoleAssignedAndStoresAppliedRoles() {
        String login = uniqueLogin();

        createUser(login, List.of("admin", "admin"))
                .then()
                .statusCode(201)
                .body("roles.size()", equalTo(1));

        var rows = pool.preparedQuery("""
                        SELECT a.action, a.details->'roles' AS roles
                        FROM keymaster.audit_log a
                        JOIN keymaster.principals p ON p.id::text = a.target_id
                        WHERE p.login = $1
                        ORDER BY a.id
                        """)
                .execute(Tuple.of(login))
                .await().atMost(TIMEOUT);

        List<String> actions = new ArrayList<>();
        String userCreatedRoles = null;

        for (var row : rows) {
            String action = row.getString("action");
            actions.add(action);

            if ("user.created".equals(action)) {
                userCreatedRoles = row.getJsonArray("roles").encode();
            }
        }

        assertEquals(List.of("user.created", "role.assigned"), actions);
        assertEquals("[\"admin\"]", userCreatedRoles);
    }

    @Test
    void rejectsWeakPasswordBeforeHashing() {
        given()
                .contentType(ContentType.JSON)
                .header("X-User-Id", UUID.randomUUID().toString())
                .header("X-User-Roles", "admin")
                .body(Map.of(
                        "login", uniqueLogin(),
                        "password", "short",
                        "roles", List.of("admin")
                ))
                .when()
                .post("/admin/users")
                .then()
                .statusCode(400)
                .body("error", equalTo("PASSWORD_POLICY_VIOLATION"))
                .body("details.size()", greaterThan(0));
    }

    private io.restassured.response.Response createUser(String login) {
        return createUser(login, List.of("admin"));
    }

    private io.restassured.response.Response createUser(String login, List<String> roles) {
        return given()
                .contentType(ContentType.JSON)
                .header("X-User-Id", UUID.randomUUID().toString())
                .header("X-User-Roles", "admin")
                .body(Map.of(
                        "login", login,
                        "password", VALID_PASSWORD,
                        "roles", roles
                ))
                .when()
                .post("/admin/users")
                .then()
                .extract()
                .response();
    }

    private String uniqueLogin() {
        return "u-" + UUID.randomUUID().toString().substring(0, 8);
    }
}
