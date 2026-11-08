package ru.zeker.keymaster.resource;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.vertx.mutiny.sqlclient.Tuple;
import org.junit.jupiter.api.Test;
import ru.zeker.keymaster.IntegrationTestBase;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;

@QuarkusTest
class UserRegistrationTest extends IntegrationTestBase {

    @Test
    void createsUserWithRoles() {
        String login = uniqueLogin();

        createUser(login, List.of("admin"))
                .then()
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

        postUser(login, List.of("admin"))
                .then()
                .statusCode(201);

        postUser(login, List.of("admin"))
                .then()
                .statusCode(409)
                .body("error", equalTo("LOGIN_ALREADY_EXISTS"))
                .body("message", equalTo("Login already exists"));
    }

    @Test
    void rejectsUnknownRoleWithoutInsertingPrincipal() {
        String login = uniqueLogin();

        adminRequest()
                .contentType(ContentType.JSON)
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

        assertEquals(0L, count("""
                SELECT count(*) AS c
                FROM keymaster.principal
                WHERE login = $1
                """, login));
    }

    @Test
    void writesUserCreatedBeforeRoleAssignedAndStoresAppliedRoles() {
        String login = uniqueLogin();

        createUser(login, List.of("admin", "admin"))
                .then()
                .body("roles.size()", equalTo(1));

        var rows = pool.preparedQuery("""
                        SELECT a.action, a.details->'roles' AS roles
                        FROM keymaster.audit_log a
                        JOIN keymaster.principal p ON p.id::text = a.target_id
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
        String login = uniqueLogin();

        adminRequest()
                .contentType(ContentType.JSON)
                .body(Map.of(
                        "login", login,
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
}
