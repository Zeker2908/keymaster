package ru.zeker.keymaster.domain.key;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

public final class KeyLifecycle {

    private final Duration pollInterval;
    private final Duration leeway;
    private final Duration maxAccessTtl;

    public KeyLifecycle(Duration pollInterval, Duration leeway, Duration maxAccessTtl) {
        this.pollInterval = requirePositive(pollInterval, "pollInterval");
        this.leeway = requireNonNegative(leeway, "leeway");
        this.maxAccessTtl = requirePositive(maxAccessTtl, "maxAccessTtl");
    }

    public KeyState stateAt(KeyTimeline t, Instant now) {
        Objects.requireNonNull(t, "timeline");
        Objects.requireNonNull(now, "now");

        if (reached(t.revokedAt(), now)) {
            return KeyState.REVOKED;
        }
        if (reached(t.removeAt(), now)) {
            return KeyState.REMOVED;
        }
        if (reached(t.retireAt(), now)) {
            return KeyState.RETIRED;
        }
        if (reached(t.activateAt(), now)) {
            return KeyState.ACTIVE;
        }
        if (reached(t.publishAt(), now)) {
            return KeyState.PLANNED;
        }
        return KeyState.PENDING;
    }

    public boolean isPublished(KeyState state) {
        return switch (Objects.requireNonNull(state, "state")) {
            case PLANNED, ACTIVE, RETIRED -> true;
            case PENDING, REMOVED, REVOKED -> false;
        };
    }

    public boolean isSigning(KeyState state) {
        return KeyState.ACTIVE == state;
    }

    public Duration publishLead() {
        return pollInterval.multipliedBy(2);
    }

    public Duration removeDelay() {
        return maxAccessTtl.plus(leeway).plus(pollInterval);
    }

    public void validate(KeyTimeline timeline, boolean initialKey) {
        Objects.requireNonNull(timeline, "timeline");

        if (!initialKey && Duration.between(timeline.publishAt(), timeline.activateAt())
                .compareTo(publishLead()) < 0) {
            throw new IllegalArgumentException(
                    "Activation must be scheduled at least " + publishLead() + " after publication"
            );
        }

        if (timeline.removeAt() != null
                && Duration.between(timeline.retireAt(), timeline.removeAt())
                .compareTo(removeDelay()) < 0) {
            throw new IllegalArgumentException(
                    "Removal must be scheduled at least " + removeDelay() + " after retirement"
            );
        }
    }

    private static boolean reached(Instant mark, Instant now) {
        return mark != null && !now.isBefore(mark);
    }

    private static Duration requirePositive(Duration value, String name) {
        Objects.requireNonNull(value, name + " must not be null");
        if (value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException(name + " must be positive");
        }
        return value;
    }

    private static Duration requireNonNegative(Duration value, String name) {
        Objects.requireNonNull(value, name + " must not be null");
        if (value.isNegative()) {
            throw new IllegalArgumentException(name + " must not be negative");
        }
        return value;
    }
}
