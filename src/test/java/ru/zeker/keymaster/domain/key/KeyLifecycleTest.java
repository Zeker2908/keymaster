package ru.zeker.keymaster.domain.key;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.Duration;
import java.time.Instant;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyLifecycleTest {

    private static final Duration POLL_INTERVAL = Duration.ofSeconds(30);
    private static final Duration LEEWAY = Duration.ofSeconds(10);
    private static final Duration MAX_ACCESS_TTL = Duration.ofMinutes(10);

    private static final Duration PUBLISH_LEAD = Duration.ofMinutes(1);
    private static final Duration REMOVE_DELAY = Duration.ofMinutes(10).plusSeconds(40);

    private static final Instant PUBLISH_AT = Instant.parse("2026-01-01T00:00:00Z");
    private static final Instant ACTIVATE_AT = PUBLISH_AT.plus(PUBLISH_LEAD);
    private static final Instant RETIRE_AT = ACTIVATE_AT.plus(Duration.ofHours(1));
    private static final Instant REMOVE_AT = RETIRE_AT.plus(REMOVE_DELAY);

    private final KeyLifecycle lifecycle = new KeyLifecycle(POLL_INTERVAL, LEEWAY, MAX_ACCESS_TTL);

    // --- конструктор ---

    @Test
    void rejectsNullPollInterval() {
        assertThrows(NullPointerException.class,
                () -> new KeyLifecycle(null, LEEWAY, MAX_ACCESS_TTL));
    }

    @Test
    void rejectsNullLeeway() {
        assertThrows(NullPointerException.class,
                () -> new KeyLifecycle(POLL_INTERVAL, null, MAX_ACCESS_TTL));
    }

    @Test
    void rejectsNullMaxAccessTtl() {
        assertThrows(NullPointerException.class,
                () -> new KeyLifecycle(POLL_INTERVAL, LEEWAY, null));
    }

    @ParameterizedTest(name = "pollInterval={0}")
    @MethodSource("nonPositiveDurations")
    void rejectsNonPositivePollInterval(Duration pollInterval) {
        assertThrows(IllegalArgumentException.class,
                () -> new KeyLifecycle(pollInterval, LEEWAY, MAX_ACCESS_TTL));
    }

    @ParameterizedTest(name = "maxAccessTtl={0}")
    @MethodSource("nonPositiveDurations")
    void rejectsNonPositiveMaxAccessTtl(Duration maxAccessTtl) {
        assertThrows(IllegalArgumentException.class,
                () -> new KeyLifecycle(POLL_INTERVAL, LEEWAY, maxAccessTtl));
    }

    @ParameterizedTest(name = "leeway={0}")
    @MethodSource("negativeDurations")
    void rejectsNegativeLeeway(Duration leeway) {
        assertThrows(IllegalArgumentException.class,
                () -> new KeyLifecycle(POLL_INTERVAL, leeway, MAX_ACCESS_TTL));
    }

    @Test
    void acceptsZeroLeeway() {
        assertDoesNotThrow(() -> new KeyLifecycle(POLL_INTERVAL, Duration.ZERO, MAX_ACCESS_TTL));
    }

    // --- stateAt ---

    @ParameterizedTest(name = "{0} -> {1}")
    @MethodSource("stateBoundaries")
    void stateChangesExactlyAtTimelineMarks(Instant now, KeyState expected) {
        assertEquals(expected, lifecycle.stateAt(fullTimeline(null), now));
    }

    @Test
    void ignoresMissingOptionalMarks() {
        KeyTimeline timeline = new KeyTimeline(PUBLISH_AT, ACTIVATE_AT, null, null, null);

        assertEquals(KeyState.PENDING, lifecycle.stateAt(timeline, PUBLISH_AT.minusNanos(1)));
        assertEquals(KeyState.PLANNED, lifecycle.stateAt(timeline, PUBLISH_AT));
        assertEquals(KeyState.ACTIVE, lifecycle.stateAt(timeline, ACTIVATE_AT));
        assertEquals(KeyState.ACTIVE, lifecycle.stateAt(timeline, ACTIVATE_AT.plus(Duration.ofDays(365))));
    }

    @Test
    void revocationWinsOverActive() {
        Instant revokedAt = ACTIVATE_AT.plusSeconds(1);
        KeyTimeline timeline = fullTimeline(revokedAt);

        assertEquals(KeyState.ACTIVE, lifecycle.stateAt(timeline, revokedAt.minusNanos(1)));
        assertEquals(KeyState.REVOKED, lifecycle.stateAt(timeline, revokedAt));
    }

    @Test
    void revocationWinsOverRetiredAndRemoved() {
        Instant revokedAt = RETIRE_AT.plusSeconds(30);
        KeyTimeline timeline = fullTimeline(revokedAt);

        assertEquals(KeyState.RETIRED, lifecycle.stateAt(timeline, revokedAt.minusNanos(1)));
        assertEquals(KeyState.REVOKED, lifecycle.stateAt(timeline, revokedAt));
        assertEquals(KeyState.REVOKED, lifecycle.stateAt(timeline, REMOVE_AT.plusSeconds(1)));
    }

    @Test
    void revocationAtPublicationTimeWinsOverPlanned() {
        KeyTimeline timeline = fullTimeline(PUBLISH_AT);

        assertEquals(KeyState.PENDING, lifecycle.stateAt(timeline, PUBLISH_AT.minusNanos(1)));
        assertEquals(KeyState.REVOKED, lifecycle.stateAt(timeline, PUBLISH_AT));
    }

    @Test
    void stateAtRejectsNullArguments() {
        assertThrows(NullPointerException.class, () -> lifecycle.stateAt(null, PUBLISH_AT));
        assertThrows(NullPointerException.class, () -> lifecycle.stateAt(fullTimeline(null), null));
    }

    // --- isPublished / isSigning ---

    @ParameterizedTest(name = "{0} -> published={1}")
    @CsvSource({
            "PENDING,false",
            "PLANNED,true",
            "ACTIVE,true",
            "RETIRED,true",
            "REMOVED,false",
            "REVOKED,false"
    })
    void onlyPlannedActiveAndRetiredArePublished(KeyState state, boolean expected) {
        assertEquals(expected, lifecycle.isPublished(state));
    }

    @Test
    void isPublishedRejectsNullState() {
        assertThrows(NullPointerException.class, () -> lifecycle.isPublished(null));
    }

    @ParameterizedTest(name = "{0} -> signing={1}")
    @CsvSource({
            "PENDING,false",
            "PLANNED,false",
            "ACTIVE,true",
            "RETIRED,false",
            "REMOVED,false",
            "REVOKED,false"
    })
    void onlyActiveIsSigning(KeyState state, boolean expected) {
        assertEquals(expected, lifecycle.isSigning(state));
    }

    // --- publishLead / removeDelay ---

    @ParameterizedTest(name = "poll={0}, leeway={1}, ttl={2}")
    @MethodSource("durationSamples")
    void derivesPublishLeadAndRemoveDelay(
            Duration pollInterval,
            Duration leeway,
            Duration maxAccessTtl,
            Duration expectedLead,
            Duration expectedRemoveDelay
    ) {
        KeyLifecycle custom = new KeyLifecycle(pollInterval, leeway, maxAccessTtl);

        assertEquals(expectedLead, custom.publishLead());
        assertEquals(expectedRemoveDelay, custom.removeDelay());
    }

    // --- validate ---

    @Test
    void acceptsTimelineAtExactBoundaries() {
        assertDoesNotThrow(() -> lifecycle.validate(fullTimeline(null), false));
        assertDoesNotThrow(() -> lifecycle.validate(fullTimeline(null), true));
    }

    @Test
    void rejectsActivationEarlierThanPublishLead() {
        KeyTimeline timeline = new KeyTimeline(
                PUBLISH_AT,
                PUBLISH_AT.plus(PUBLISH_LEAD).minusNanos(1),
                null,
                null,
                null
        );

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> lifecycle.validate(timeline, false));

        assertTrue(exception.getMessage().contains("Activation must be scheduled at least"));
        assertTrue(exception.getMessage().contains(lifecycle.publishLead().toString()));
    }

    @Test
    void allowsShortActivationLeadForInitialKey() {
        KeyTimeline timeline = new KeyTimeline(
                PUBLISH_AT,
                PUBLISH_AT.plusSeconds(1),
                null,
                null,
                null
        );

        assertDoesNotThrow(() -> lifecycle.validate(timeline, true));
    }

    @Test
    void rejectsRemovalEarlierThanRemoveDelay() {
        KeyTimeline timeline = new KeyTimeline(
                PUBLISH_AT,
                ACTIVATE_AT,
                RETIRE_AT,
                RETIRE_AT.plus(REMOVE_DELAY).minusNanos(1),
                null
        );

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> lifecycle.validate(timeline, false));

        assertTrue(exception.getMessage().contains("Removal must be scheduled at least"));
        assertTrue(exception.getMessage().contains(lifecycle.removeDelay().toString()));
    }

    @Test
    void validatesRemovalDelayForInitialKeyToo() {
        KeyTimeline timeline = new KeyTimeline(
                PUBLISH_AT,
                ACTIVATE_AT,
                RETIRE_AT,
                RETIRE_AT.plus(REMOVE_DELAY).minusNanos(1),
                null
        );

        assertThrows(IllegalArgumentException.class,
                () -> lifecycle.validate(timeline, true));
    }

    @Test
    void skipsRemovalCheckWhenRemovalIsNotScheduled() {
        KeyTimeline timeline = new KeyTimeline(PUBLISH_AT, ACTIVATE_AT, RETIRE_AT, null, null);

        assertDoesNotThrow(() -> lifecycle.validate(timeline, false));
    }

    @Test
    void validateRejectsNullTimeline() {
        assertThrows(NullPointerException.class, () -> lifecycle.validate(null, false));
        assertThrows(NullPointerException.class, () -> lifecycle.validate(null, true));
    }

    // --- фабрики тестовых данных ---

    private static KeyTimeline fullTimeline(Instant revokedAt) {
        return new KeyTimeline(PUBLISH_AT, ACTIVATE_AT, RETIRE_AT, REMOVE_AT, revokedAt);
    }

    private static Stream<Duration> nonPositiveDurations() {
        return Stream.of(Duration.ZERO, Duration.ofNanos(-1), Duration.ofSeconds(-1));
    }

    private static Stream<Duration> negativeDurations() {
        return Stream.of(Duration.ofNanos(-1), Duration.ofSeconds(-1));
    }

    private static Stream<Arguments> stateBoundaries() {
        return Stream.of(
                Arguments.of(PUBLISH_AT.minusNanos(1), KeyState.PENDING),
                Arguments.of(PUBLISH_AT, KeyState.PLANNED),
                Arguments.of(ACTIVATE_AT.minusNanos(1), KeyState.PLANNED),
                Arguments.of(ACTIVATE_AT, KeyState.ACTIVE),
                Arguments.of(RETIRE_AT.minusNanos(1), KeyState.ACTIVE),
                Arguments.of(RETIRE_AT, KeyState.RETIRED),
                Arguments.of(REMOVE_AT.minusNanos(1), KeyState.RETIRED),
                Arguments.of(REMOVE_AT, KeyState.REMOVED),
                Arguments.of(REMOVE_AT.plusSeconds(3600), KeyState.REMOVED)
        );
    }

    private static Stream<Arguments> durationSamples() {
        return Stream.of(
                Arguments.of(
                        POLL_INTERVAL, LEEWAY, MAX_ACCESS_TTL,
                        PUBLISH_LEAD, REMOVE_DELAY
                ),
                Arguments.of(
                        Duration.ofSeconds(1), Duration.ZERO, Duration.ofSeconds(5),
                        Duration.ofSeconds(2), Duration.ofSeconds(6)
                )
        );
    }
}
