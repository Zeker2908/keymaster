package ru.zeker.keymaster.service.key;

import io.quarkus.test.junit.QuarkusMock;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.vertx.VertxContextSupport;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import ru.zeker.keymaster.domain.Algorithm;
import ru.zeker.keymaster.exception.ErrorCode;
import ru.zeker.keymaster.exception.KeyMasterException;
import ru.zeker.keymaster.repository.SigningKeyRepository;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@QuarkusTest
class SigningKeyServiceRaceTest {

    private static final Duration TIMEOUT = Duration.ofSeconds(20);

    @Inject
    SigningKeyService keys;

    @Test
    void treatsScheduleConflictAsSuccessWhenAnotherInstanceCreatedKey() throws Throwable {
        SigningKeyRepository repository = mock(SigningKeyRepository.class);
        when(repository.existsAny())
                .thenReturn(Uni.createFrom().item(false))
                .thenReturn(Uni.createFrom().item(true));
        when(repository.create(any()))
                .thenReturn(Uni.createFrom().failure(scheduleConflict()));
        QuarkusMock.installMockForType(repository, SigningKeyRepository.class);

        boolean created = VertxContextSupport.subscribeAndAwait(() -> keys.ensureInitialKey(Algorithm.RS256)
                .ifNoItem()
                .after(TIMEOUT)
                .fail());

        assertFalse(created);
        verify(repository, times(2)).existsAny();
    }

    @Test
    void failsWhenScheduleConflictLeavesNoKey() throws Throwable {
        SigningKeyRepository repository = mock(SigningKeyRepository.class);
        when(repository.existsAny())
                .thenReturn(Uni.createFrom().item(false));
        when(repository.create(any()))
                .thenReturn(Uni.createFrom().failure(scheduleConflict()));
        QuarkusMock.installMockForType(repository, SigningKeyRepository.class);

        Throwable failure = assertThrows(Throwable.class, () ->
                VertxContextSupport.subscribeAndAwait(() -> keys.ensureInitialKey(Algorithm.RS256)
                        .ifNoItem()
                        .after(TIMEOUT)
                        .fail()));

        assertTrue(hasMessage(failure, "no signing key exists"),
                () -> "unexpected failure: " + failure);
        verify(repository, times(2)).existsAny();
    }

    /** Репозиторий уже транслирует SQLSTATE в доменную ошибку на своей границе. */
    private static KeyMasterException scheduleConflict() {
        return new KeyMasterException(ErrorCode.KEY_SCHEDULE_CONFLICT);
    }

    private static boolean hasMessage(Throwable failure, String fragment) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause.getMessage() != null && cause.getMessage().contains(fragment)) {
                return true;
            }
        }
        return false;
    }
}
