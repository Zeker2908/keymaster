package ru.zeker.keymaster.resource;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.IntStream;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;

@QuarkusTest
class RequestIdTest {

    @Test
    void shouldPropagateRequestIdThroughReactiveExecution() {
        given()
                .header("X-Request-Id", "test-request-123")
                .when()
                .get("/test/mdc")
                .then()
                .statusCode(200)
                .body(equalTo("test-request-123"))
                .header("X-Request-Id", equalTo("test-request-123"));
    }

    @Test
    void shouldGenerateRequestIdWhenHeaderIsMissing() {
        Response response = given()
                .when()
                .get("/test/mdc")
                .then()
                .statusCode(200)
                .header("X-Request-Id", notNullValue())
                .extract()
                .response();

        String headerId = response.header("X-Request-Id");
        String bodyId = response.asString();

        // MDC внутри обработчика должен совпадать с заголовком ответа
        assertEquals(headerId, bodyId);

        // Сгенерированный id принимается и возвращается как есть
        given()
                .header("X-Request-Id", headerId)
                .when()
                .get("/test/mdc")
                .then()
                .statusCode(200)
                .body(equalTo(headerId))
                .header("X-Request-Id", equalTo(headerId));
    }

    @Test
    void shouldReplaceRequestIdContainingSpaces() {
        given()
                .header("X-Request-Id", "invalid request id")
                .when()
                .get("/test/mdc")
                .then()
                .statusCode(200)
                .body(not(equalTo("invalid request id")))
                .header("X-Request-Id", not(equalTo("invalid request id")));
    }

    @Test
    void shouldReplaceTooLongRequestId() {
        String requestId = "a".repeat(129);

        given()
                .header("X-Request-Id", requestId)
                .when()
                .get("/test/mdc")
                .then()
                .statusCode(200)
                .body(not(equalTo(requestId)))
                .header("X-Request-Id", not(equalTo(requestId)));
    }

    @Test
    void shouldKeepRequestIdsIsolatedAcrossConcurrentRequests() throws Exception {
        int count = 20;
        CountDownLatch startSignal = new CountDownLatch(1);

        try (ExecutorService executor = Executors.newFixedThreadPool(count)) {
            List<CompletableFuture<Map.Entry<String, String>>> requests = IntStream.range(0, count)
                    .mapToObj(i -> {
                        String requestId = "parallel-request-" + i;

                        return CompletableFuture.supplyAsync(() -> {
                            try {
                                // Все запросы стартуют одновременно
                                startSignal.await();
                            } catch (InterruptedException e) {
                                Thread.currentThread().interrupt();
                                throw new IllegalStateException(e);
                            }

                            String responseId = given()
                                    .header("X-Request-Id", requestId)
                                    .when()
                                    .get("/test/mdc/delay")
                                    .then()
                                    .statusCode(200)
                                    .header("X-Request-Id", equalTo(requestId))
                                    .extract()
                                    .asString();

                            return Map.entry(requestId, responseId);
                        }, executor);
                    })
                    .toList();

            startSignal.countDown();

            requests.stream()
                    .map(CompletableFuture::join)
                    .forEach(result -> assertEquals(result.getKey(), result.getValue()));
        }
    }

    @Test
    void shouldReturnRequestIdInNotFoundResponse() {
        given()
                .header("X-Request-Id", "not-found-request")
                .when()
                .get("/does-not-exist")
                .then()
                .statusCode(404)
                .header("X-Request-Id", equalTo("not-found-request"))
                .body("requestId", equalTo("not-found-request"))
                .body("status", equalTo(404));
    }

    @Test
    void shouldNotExposeInternalExceptionDetails() {
        given()
                .header("X-Request-Id", "internal-error-request")
                .when()
                .get("/test/fail")
                .then()
                .statusCode(500)
                .header("X-Request-Id", equalTo("internal-error-request"))
                .body("requestId", equalTo("internal-error-request"))
                .body("status", equalTo(500))
                .body(not(containsString("Sensitive internal details")))
                .body(not(containsString("IllegalStateException")))
                .body(not(containsString("at ru.zeker.keymaster")));
    }

    @Test
    void shouldReturn400ForMalformedJson() {
        given()
                .contentType(ContentType.JSON)
                .body("\"login\"")
                .when()
                .post("/test/json")
                .then()
                .statusCode(400);
    }

    @Test
    void shouldReturn415ForUnsupportedContentType() {
        given()
                .contentType(ContentType.TEXT)
                .body("plain text")
                .when()
                .post("/test/json")
                .then()
                .statusCode(415);
    }

    @Test
    void shouldReportApplicationReady() {
        given()
                .when()
                .get("/q/health/ready")
                .then()
                .statusCode(200)
                .body("status", equalTo("UP"));
    }
}
