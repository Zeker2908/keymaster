package ru.zeker.keymaster.resource;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import io.vertx.mutiny.sqlclient.Tuple;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import ru.zeker.keymaster.IntegrationTestBase;
import ru.zeker.keymaster.config.KeysConfig;
import ru.zeker.keymaster.domain.Algorithm;
import ru.zeker.keymaster.service.key.SigningKeyService;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
class LoginIntegrationTest extends IntegrationTestBase {

    private static final String WRONG_PASSWORD = "wrong-password-1!";

    @Inject
    SigningKeyService signingKeys;

    @Inject
    KeysConfig config;

    @BeforeEach
    void ensureActiveSigningKey() throws Throwable {
        io.quarkus.vertx.VertxContextSupport.subscribeAndAwait(
                () -> signingKeys.ensureInitialKey(Algorithm.RS256)
                        .ifNoItem()
                        .after(TIMEOUT)
                        .fail());
    }

    @Test
    void returnsSignedAccessTokenWithoutRefreshToken() throws Exception {
        String role = uniqueRoleName();
        createRole(role).then().statusCode(201);

        Response created = createUser(List.of(role));
        UUID userId = UUID.fromString(created.jsonPath().getString("id"));
        String login = created.jsonPath().getString("login");

        Response response = login(login, VALID_PASSWORD);

        response.then()
                .statusCode(200)
                .body("accessToken", not(emptyOrNullString()))
                .body("tokenType", equalTo("Bearer"))
                .body("expiresIn", equalTo((int) config.maxAccessTtl().toSeconds()))
                .body("refreshToken", nullValue());

        assertEquals(
                Set.of("accessToken", "tokenType", "expiresIn"),
                response.jsonPath().getMap("$").keySet(),
                "login must not expose a refresh token until stage 6"
        );

        SignedJWT token = SignedJWT.parse(response.jsonPath().getString("accessToken"));
        JWKSet jwks = fetchJwks();
        JWK jwk = jwks.getKeyByKeyId(token.getHeader().getKeyID());

        assertNotNull(jwk, () -> "token kid is not published in JWKS: "
                + token.getHeader().getKeyID());
        assertTrue(token.verify(new RSASSAVerifier(jwk.toRSAKey())),
                "access token signature must verify with a published key");

        JWTClaimsSet claims = token.getJWTClaimsSet();
        assertEquals(userId.toString(), claims.getSubject());
        assertEquals("http://keymaster", claims.getIssuer());
        assertEquals(List.of("gatekeeper"), claims.getAudience());
        assertEquals(List.of(role), claims.getStringListClaim("roles"));
        assertNotNull(claims.getJWTID());
        assertNotNull(claims.getIssueTime());
        assertNotNull(claims.getExpirationTime());

        long lifetime = Duration.between(
                claims.getIssueTime().toInstant(),
                claims.getExpirationTime().toInstant()
        ).toSeconds();

        assertEquals(config.maxAccessTtl().toSeconds(), lifetime);
    }

    @Test
    void invalidCredentialsAreIndistinguishableForUnknownWrongDisabledAndClient() {
        Response created = createUser(List.of());
        UUID userId = UUID.fromString(created.jsonPath().getString("id"));
        String login = created.jsonPath().getString("login");

        Response wrongPassword = login(login, WRONG_PASSWORD);

        updatePrincipal(userId, "UPDATE keymaster.principal SET status = 'DISABLED' WHERE id = $1");
        Response disabled = login(login, VALID_PASSWORD);

        updatePrincipal(userId,
                "UPDATE keymaster.principal SET kind = 'CLIENT', status = 'ACTIVE' WHERE id = $1");
        Response client = login(login, VALID_PASSWORD);

        Response unknown = login(uniqueLogin(), VALID_PASSWORD);

        List<Response> responses = List.of(wrongPassword, disabled, client, unknown);
        responses.forEach(LoginIntegrationTest::assertInvalidCredentials);

        for (Response response : responses.subList(1, responses.size())) {
            assertSameError(wrongPassword, response);
        }
    }

    @Test
    void rejectsRequestsWithMissingOrBlankCredentials() {
        given()
                .contentType(ContentType.JSON)
                .body("{}")
                .when()
                .post("/v1/auth/login")
                .then()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("details.size()", greaterThanOrEqualTo(2));

        given()
                .contentType(ContentType.JSON)
                .body(Map.of("login", "   ", "password", "password-1!"))
                .when()
                .post("/v1/auth/login")
                .then()
                .statusCode(400)
                .body("error", equalTo("Bad Request"))
                .body("details[0].field", notNullValue());
    }

    private Response login(String login, String password) {
        return login(login, password, null);
    }

    private Response login(String login, String password, String requestId) {
        RequestSpecification request = given()
                .contentType(ContentType.JSON);

        if (requestId != null) {
            request.header("X-Request-Id", requestId);
        }

        return request
                .body(Map.of("login", login, "password", password))
                .when()
                .post("/v1/auth/login");
    }

    private JWKSet fetchJwks() throws Exception {
        String body = given()
                .when()
                .get("/v1/jwks")
                .then()
                .statusCode(200)
                .extract()
                .asString();

        return JWKSet.parse(body);
    }

    private void updatePrincipal(UUID id, String sql) {
        pool.preparedQuery(sql)
                .execute(Tuple.of(id))
                .await().atMost(TIMEOUT);
    }

    private long totalAuditRows() {
        return count("SELECT count(*) AS c FROM keymaster.audit_log");
    }

    private static String uniqueRoleName() {
        return "login-" + UUID.randomUUID().toString().substring(0, 8);
    }

    private static void assertInvalidCredentials(Response response) {
        response.then()
                .statusCode(401)
                .body("error", equalTo("INVALID_CREDENTIALS"))
                .body("message", equalTo("Invalid login or password"))
                .body("status", equalTo(401))
                .body("accessToken", nullValue())
                .body("refreshToken", nullValue());
    }

    private static void assertSameError(Response expected, Response actual) {
        assertEquals(
                expected.jsonPath().getInt("status"),
                actual.jsonPath().getInt("status")
        );
        assertEquals(
                expected.jsonPath().getString("error"),
                actual.jsonPath().getString("error")
        );
        assertEquals(
                expected.jsonPath().getString("message"),
                actual.jsonPath().getString("message")
        );
    }

    private static final class CapturingHandler extends Handler {

        private final StringBuilder messages = new StringBuilder();

        private CapturingHandler() {
            setLevel(Level.ALL);
        }

        @Override
        public void publish(LogRecord record) {
            messages.append(record.getMessage()).append('\n');
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
        }

        private String text() {
            return messages.toString();
        }
    }
}
