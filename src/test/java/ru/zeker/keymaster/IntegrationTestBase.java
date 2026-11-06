package ru.zeker.keymaster;

import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import io.vertx.mutiny.sqlclient.Pool;
import io.vertx.mutiny.sqlclient.Tuple;
import jakarta.inject.Inject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Общий базовый класс интеграционных тестов.
 *
 * <p>Хелперы:</p>
 * <ul>
 *   <li>{@link #adminRequest()} — запрос от имени админа;</li>
 *   <li>{@link #createUser(List)}/{@link #postUser(Map)} — создание пользователя
 *       через {@code POST /admin/users};</li>
 *   <li>{@link #createRole(String)} — создание роли через {@code POST /admin/admin/roles};</li>
 *   <li>{@link #count(String, Object)} — подсчёт строк в БД;</li>
 *   <li>{@link #uniqueLogin()} — уникальный логин для теста.</li>
 * </ul>
 *
 * <p>Чистка после каждого теста: удаляются пользователи и роли, созданные в течение
 * теста (в том числе пользователи с ролью {@code admin}), а назначения роли
 * {@code admin} возвращаются к состоянию до теста — тесты, вычищающие админов
 * напрямую через SQL, не ломают последующие тесты.</p>
 */
public abstract class IntegrationTestBase {

    protected static final Duration TIMEOUT = Duration.ofSeconds(20);
    protected static final String VALID_PASSWORD = "correct-horse-1!";
    protected static final String USER_ID_HEADER = "X-User-Id";
    protected static final String USER_ROLES_HEADER = "X-User-Roles";

    @Inject
    protected Pool pool;

    /**
     * Пользователи, созданные в течение теста. Копия на запись: создание может идти
     * из нескольких потоков (параллельные запросы).
     */
    private final List<UUID> createdPrincipals = new CopyOnWriteArrayList<>();

    /** Роли, созданные в течение теста. */
    private final List<String> createdRoles = new CopyOnWriteArrayList<>();

    /** Назначения роли admin до теста; {@code null}, если снапшот не сделан. */
    private List<UUID> adminsBeforeTest;

    @BeforeEach
    protected void rememberStateBeforeTest() {
        createdPrincipals.clear();
        createdRoles.clear();
        // если снапшот не удался, чистку админов пропускаем, чтобы не затереть состояние БД
        adminsBeforeTest = null;
        adminsBeforeTest = principalsWithAdminRole();
    }

    @AfterEach
    protected void cleanUpCreatedData() {
        try {
            // сначала пользователи: principal_role удаляется каскадно вместе с ними
            createdPrincipals.forEach(this::deletePrincipal);
            // затем роли: principal_role ссылается на role (ON DELETE RESTRICT)
            createdRoles.forEach(this::deleteRole);
        } finally {
            createdPrincipals.clear();
            createdRoles.clear();
            if (adminsBeforeTest != null) {
                restoreAdminAssignments(adminsBeforeTest);
            }
        }
    }

    // --- HTTP-хелперы ---

    /** Запрос от имени админа со случайным actor id. */
    protected RequestSpecification adminRequest() {
        return adminRequest(UUID.randomUUID());
    }

    /** Запрос от имени админа с указанным actor id. */
    protected RequestSpecification adminRequest(UUID actorId) {
        return given()
                .header(USER_ID_HEADER, actorId.toString())
                .header(USER_ROLES_HEADER, "admin");
    }

    /**
     * {@code POST /admin/users} без проверки статуса. При ответе 201 пользователь
     * регистрируется для чистки.
     */
    protected Response postUser(Map<String, Object> body) {
        Response response = adminRequest()
                .contentType(ContentType.JSON)
                .body(body)
                .when()
                .post("/admin/users");

        if (response.statusCode() == 201) {
            createdPrincipals.add(UUID.fromString(response.jsonPath().getString("id")));
        }
        return response;
    }

    /** {@code POST /admin/users} без проверки статуса. */
    protected Response postUser(String login, List<String> roles) {
        return postUser(Map.of(
                "login", login,
                "password", VALID_PASSWORD,
                "roles", roles
        ));
    }

    /** Создаёт пользователя с уникальным логином; требует ответа 201. */
    protected Response createUser(List<String> roles) {
        return createUser(uniqueLogin(), roles);
    }

    /** Создаёт пользователя; требует ответа 201. */
    protected Response createUser(String login, List<String> roles) {
        Response response = postUser(login, roles);
        assertEquals(201, response.statusCode(),
                () -> "creating user '" + login + "' failed: " + response.asString());
        return response;
    }

    /** {@code POST /admin/admin/roles}; при ответе 201 роль регистрируется для чистки. */
    protected Response createRole(String name) {
        Response response = adminRequest()
                .contentType(ContentType.JSON)
                .body(Map.of(
                        "name", name,
                        "description", "Test role"
                ))
                .when()
                .post("/admin/admin/roles");

        if (response.statusCode() == 201) {
            createdRoles.add(name);
        }
        return response;
    }

    // --- хелперы по БД ---

    /** Считает колонку {@code c} первой строки результата. */
    protected long count(String sql, Object parameter) {
        return pool.preparedQuery(sql)
                .execute(Tuple.of(parameter))
                .map(rows -> rows.iterator().next().getLong("c"))
                .await().atMost(TIMEOUT);
    }

    /** Принципалы, которым назначена роль {@code admin}. */
    protected List<UUID> principalsWithAdminRole() {
        return pool.preparedQuery("""
                        SELECT pr.principal_id
                        FROM keymaster.principal_role pr
                        JOIN keymaster.role r ON r.id = pr.role_id
                        WHERE r.name = 'admin'
                        ORDER BY pr.principal_id
                        """)
                .execute()
                .map(rows -> {
                    List<UUID> ids = new ArrayList<>();
                    rows.forEach(row -> ids.add(row.getUUID("principal_id")));
                    return ids;
                })
                .await().atMost(TIMEOUT);
    }

    /** Уникальный логин в пределах ограничения {@code principal_login_chk}. */
    protected String uniqueLogin() {
        return "u-" + UUID.randomUUID().toString().substring(0, 8);
    }

    // --- чистка ---

    private void deletePrincipal(UUID principalId) {
        pool.preparedQuery("DELETE FROM keymaster.principal WHERE id = $1")
                .execute(Tuple.of(principalId))
                .await().atMost(TIMEOUT);
    }

    /** Удаляет роль, если на неё не осталось назначений (чтобы не падать на FK RESTRICT). */
    private void deleteRole(String name) {
        pool.preparedQuery("""
                        DELETE FROM keymaster.role r
                        WHERE r.name = $1
                          AND NOT EXISTS (
                              SELECT 1
                              FROM keymaster.principal_role pr
                              WHERE pr.role_id = r.id
                          )
                        """)
                .execute(Tuple.of(name))
                .await().atMost(TIMEOUT);
    }

    private void restoreAdminAssignments(List<UUID> principalIds) {
        pool.preparedQuery("""
                        DELETE FROM keymaster.principal_role pr
                        USING keymaster.role r
                        WHERE pr.role_id = r.id
                          AND r.name = 'admin'
                        """)
                .execute()
                .await().atMost(TIMEOUT);

        for (UUID principalId : principalIds) {
            pool.preparedQuery("""
                            INSERT INTO keymaster.principal_role (principal_id, role_id)
                            SELECT p.id, r.id
                            FROM keymaster.principal p
                            JOIN keymaster.role r ON r.name = 'admin'
                            WHERE p.id = $1
                            ON CONFLICT DO NOTHING
                            """)
                    .execute(Tuple.of(principalId))
                    .await().atMost(TIMEOUT);
        }
    }
}
