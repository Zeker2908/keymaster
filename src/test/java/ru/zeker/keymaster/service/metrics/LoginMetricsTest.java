package ru.zeker.keymaster.service.metrics;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class LoginMetricsTest {

    @Test
    void countsSuccessfulAndFailedLoginsSeparately() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        LoginMetrics metrics = new LoginMetrics(registry);

        metrics.success();
        metrics.success();
        metrics.failure();

        assertEquals(2.0, count(registry, "success"));
        assertEquals(1.0, count(registry, "failure"));
    }

    private static double count(SimpleMeterRegistry registry, String result) {
        return registry.get("keymaster.auth.login")
                .tag("result", result)
                .counter()
                .count();
    }
}
