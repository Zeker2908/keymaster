package ru.zeker.keymaster.domain.key;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import ru.zeker.keymaster.config.KeymasterConfig;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Симуляция гейтвея, кэширующего JWKS, на реальных таймингах из конфигурации.
 *
 * <p>Модель:</p>
 * <ul>
 *   <li>ротация двух ключей: A активен, B опубликован заранее на {@link KeyLifecycle#publishLead()},
 *       {@code A.retire = B.activate}, {@code A.remove = A.retire + removeDelay};</li>
 *   <li>гейтвей опрашивает JWKS в моменты {@code phase + k * poll}; успешный опрос заменяет снимок
 *       на ключи, для которых {@link KeyLifecycle#isPublished(KeyState)} в момент опроса,
 *       сорвавшийся опрос оставляет прежний снимок;</li>
 *   <li>токен, выпущенный в момент {@code t} ключом, который в {@code t} {@code ACTIVE},
 *       гейтвей может проверять в любой {@code v} из {@code [t, t + maxAccessTtl + leeway]}.</li>
 * </ul>
 *
 * <p>Проверяется одно утверждение: при наших таймингах снимок гейтвея в момент проверки всегда
 * содержит {@code kid} подписавшего ключа — при любой фазе опроса и при условии, что сорвался
 * не более одного опроса. Снимок меняется только в моменты опросов, поэтому достаточно проверить
 * {@code v = t} и каждый момент опроса из {@code (t, t + maxAccessTtl + leeway]}.</p>
 *
 * <p>Дополнительно проверяются инварианты расписания: в любой момент {@code ACTIVE}-ключ не более
 * одного и множество опубликованных ключей не пусто (пустой JWKS гейтвей отвергает).</p>
 */
@QuarkusTest
class GatewayKeyRotationSimulationTest {

    /** Шаг сетки моментов выпуска токенов. */
    private static final Duration TOKEN_STEP = Duration.ofSeconds(10);

    /** Шаг перебора фазы опроса внутри интервала {@code poll}. */
    private static final Duration PHASE_STEP = Duration.ofSeconds(5);

    /** Начало симуляции. */
    private static final Instant START = Instant.parse("2026-01-01T00:00:00Z");

    /** Ключ A активен задолго до начала симуляции (initial key). */
    private static final Duration A_WAS_ACTIVE_FOR = Duration.ofHours(1);

    /** Через сколько после начала симуляции A уходит на пенсию, а B становится активным. */
    private static final Duration ROTATION_AFTER_START = Duration.ofMinutes(30);

    @Inject
    KeyLifecycle lifecycle;

    @Inject
    KeymasterConfig config;

    private Duration pollInterval;
    private Duration leeway;
    private Duration maxAccessTtl;

    private List<SimKey> keys;
    private Instant end;

    @BeforeEach
    void setUp() {
        pollInterval = config.keys().jwksPollInterval();
        leeway = config.keys().leeway();
        maxAccessTtl = config.keys().maxAccessTtl();

        Instant activateA = START.minus(A_WAS_ACTIVE_FOR);
        Instant publishA = activateA.minus(lifecycle.publishLead());
        Instant retireA = START.plus(ROTATION_AFTER_START);
        Instant activateB = retireA;
        Instant publishB = activateB.minus(lifecycle.publishLead());
        Instant removeA = retireA.plus(lifecycle.removeDelay());

        KeyTimeline timelineA = new KeyTimeline(publishA, activateA, retireA, removeA, null);
        KeyTimeline timelineB = new KeyTimeline(publishB, activateB, null, null, null);

        // расписание обязано быть допустимым по правилам домена
        lifecycle.validate(timelineA, true);
        lifecycle.validate(timelineB, false);

        keys = List.of(new SimKey("key-a", timelineA), new SimKey("key-b", timelineB));
        end = removeA.plus(maxAccessTtl).plus(leeway);
    }

    @Test
    void scheduleHasAtMostOneActiveKeyAndAlwaysSomethingPublished() {
        Set<Instant> samples = new TreeSet<>();
        samples.add(START);
        samples.add(end);

        for (SimKey key : keys) {
            KeyTimeline timeline = key.timeline();
            Stream.of(
                            timeline.publishAt(),
                            timeline.activateAt(),
                            timeline.retireAt(),
                            timeline.removeAt(),
                            timeline.revokedAt()
                    )
                    .filter(Objects::nonNull)
                    .forEach(mark -> {
                        if (mark.isAfter(START) && mark.isBefore(end)) {
                            // состояние кусочно-постоянно, меняется только в метках таймлайна
                            samples.add(mark.minusNanos(1));
                            samples.add(mark);
                        }
                    });
        }

        samples.forEach(this::assertInvariants);
    }

    @Test
    void gatewayNeverSeesTokenSignedByKeyMissingFromItsSnapshot() {
        for (Duration phase = Duration.ZERO;
                phase.compareTo(pollInterval) < 0;
                phase = phase.plus(PHASE_STEP)) {
            simulatePollPhase(phase);
        }
    }

    // --- симуляция окружения ---

    private void simulatePollPhase(Duration phase) {
        List<Instant> polls = pollSchedule(phase);
        List<Set<String>> snapshots = polls.stream().map(this::snapshotAt).toList();

        for (Instant issuedAt = START; !issuedAt.isAfter(end); issuedAt = issuedAt.plus(TOKEN_STEP)) {
            SimKey signer = signingKeyAt(issuedAt);
            Instant verifyUntil = issuedAt.plus(maxAccessTtl).plus(leeway);

            int lastPoll = lastPollIndex(polls, issuedAt);

            // проверка сразу после выпуска: ни один опрос не сорвался / сорвался последний
            assertKeyVisible(snapshots, lastPoll, signer, issuedAt, issuedAt, phase, "no poll failed");
            assertKeyVisible(snapshots, lastPoll - 1, signer, issuedAt, issuedAt, phase,
                    "poll #" + lastPoll + " failed");

            // снимок меняется только в моменты опросов, поэтому проверяем каждый из них
            for (int i = lastPoll + 1; i < polls.size() && !polls.get(i).isAfter(verifyUntil); i++) {
                Instant verifyAt = polls.get(i);
                assertKeyVisible(snapshots, i, signer, issuedAt, verifyAt, phase, "no poll failed");
                assertKeyVisible(snapshots, i - 1, signer, issuedAt, verifyAt, phase,
                        "poll #" + i + " failed");
            }
        }
    }

    private List<Instant> pollSchedule(Duration phase) {
        Instant first = START.minus(pollInterval.multipliedBy(3)).plus(phase);
        Instant last = end.plus(maxAccessTtl).plus(leeway).plus(pollInterval);

        List<Instant> polls = new ArrayList<>();
        for (Instant at = first; !at.isAfter(last); at = at.plus(pollInterval)) {
            polls.add(at);
        }
        return polls;
    }

    /** Успешный опрос: снимок из опубликованных на момент опроса ключей. */
    private Set<String> snapshotAt(Instant at) {
        Set<String> kids = new LinkedHashSet<>();
        for (SimKey key : keys) {
            if (lifecycle.isPublished(lifecycle.stateAt(key.timeline(), at))) {
                kids.add(key.kid());
            }
        }

        assertFalse(kids.isEmpty(), () -> "gateway would reject empty JWKS at " + at);
        return Set.copyOf(kids);
    }

    private SimKey signingKeyAt(Instant at) {
        List<SimKey> active = keys.stream()
                .filter(key -> lifecycle.stateAt(key.timeline(), at) == KeyState.ACTIVE)
                .toList();

        assertEquals(1, active.size(),
                () -> "exactly one key must be ACTIVE at " + at + " to sign a token, got " + kids(active));
        return active.getFirst();
    }

    private void assertKeyVisible(
            List<Set<String>> snapshots,
            int snapshotIndex,
            SimKey signer,
            Instant issuedAt,
            Instant verifiedAt,
            Duration phase,
            String pollErrors
    ) {
        Set<String> snapshot = snapshotIndex >= 0 ? snapshots.get(snapshotIndex) : Set.of();

        assertTrue(snapshot.contains(signer.kid()),
                () -> "key '" + signer.kid() + "' signed token at " + issuedAt
                        + " but is missing from gateway JWKS at " + verifiedAt
                        + " (poll phase " + phase + ", " + pollErrors + "); snapshot=" + snapshot);
    }

    private static int lastPollIndex(List<Instant> polls, Instant at) {
        int last = -1;
        for (int i = 0; i < polls.size() && !polls.get(i).isAfter(at); i++) {
            last = i;
        }
        return last;
    }

    // --- инварианты расписания ---

    private void assertInvariants(Instant at) {
        List<SimKey> active = keys.stream()
                .filter(key -> lifecycle.stateAt(key.timeline(), at) == KeyState.ACTIVE)
                .toList();
        assertTrue(active.size() <= 1,
                () -> "more than one ACTIVE key at " + at + ": " + kids(active));

        List<SimKey> published = keys.stream()
                .filter(key -> lifecycle.isPublished(lifecycle.stateAt(key.timeline(), at)))
                .toList();
        assertFalse(published.isEmpty(),
                () -> "no published keys at " + at + ": gateway would reject an empty JWKS");
    }

    private static List<String> kids(List<SimKey> keys) {
        return keys.stream().map(SimKey::kid).toList();
    }

    private record SimKey(String kid, KeyTimeline timeline) {
    }
}
