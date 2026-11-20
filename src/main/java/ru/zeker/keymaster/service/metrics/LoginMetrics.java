package ru.zeker.keymaster.service.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
public class LoginMetrics {

    private static final String METRIC_NAME = "keymaster.auth.login";
    private static final String RESULT_TAG = "result";
    private static final String SUCCESS = "success";
    private static final String FAILURE = "failure";

    private final Counter success;
    private final Counter failure;

    @Inject
    public LoginMetrics(MeterRegistry registry) {
        this.success = counter(registry, SUCCESS);
        this.failure = counter(registry, FAILURE);
    }

    public void success() {
        success.increment();
    }

    public void failure() {
        failure.increment();
    }

    private static Counter counter(MeterRegistry registry, String result) {
        return Counter.builder(METRIC_NAME)
                .description("Login attempts by result")
                .tag(RESULT_TAG, result)
                .register(registry);
    }
}
