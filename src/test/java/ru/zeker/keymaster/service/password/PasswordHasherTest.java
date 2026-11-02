package ru.zeker.keymaster.service.password;

import de.mkammerer.argon2.Argon2;
import io.smallrye.mutiny.helpers.test.UniAssertSubscriber;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import ru.zeker.keymaster.config.KeymasterConfig;
import ru.zeker.keymaster.exception.ServiceOverloadedException;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.AbstractExecutorService;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PasswordHasherTest {

    private static final int CONCURRENCY_LIMIT = 4;

    private Argon2 argon2;
    private KeymasterConfig config;
    private ExecutorService executor;
    private PasswordHasher hasher;

    @BeforeEach
    void setUp() {
        argon2 = mock(Argon2.class);
        config = mock(KeymasterConfig.class, RETURNS_DEEP_STUBS);
        executor = new DirectExecutorService();

        when(config.password().argon2().iterations()).thenReturn(2);
        when(config.password().argon2().memory()).thenReturn(19456);
        when(config.password().argon2().parallelism()).thenReturn(1);

        hasher = new PasswordHasher(argon2, config, executor);
    }

    @Test
    void hash_shouldReturnHashAndWipePassword() {
        char[] password = "password123".toCharArray();
        AtomicReference<char[]> normalized = new AtomicReference<>();
        String expectedHash = "$argon2id$test";

        when(argon2.hash(anyInt(), anyInt(), anyInt(), any(char[].class), eq(StandardCharsets.UTF_8)))
                .thenAnswer(invocation -> {
                    normalized.set(invocation.getArgument(3));
                    return expectedHash;
                });

        String result = hasher.hash(password).await().indefinitely();

        assertEquals(expectedHash, result);
        assertWiped(password);
        assertWiped(normalized.get());

        verify(argon2).hash(anyInt(), anyInt(), anyInt(), any(char[].class), eq(StandardCharsets.UTF_8));
    }

    @Test
    void verify_shouldReturnTrueAndWipePassword() {
        char[] password = "password123".toCharArray();
        AtomicReference<char[]> normalized = new AtomicReference<>();
        String hash = "$argon2id$test";

        when(argon2.verify(eq(hash), any(char[].class)))
                .thenAnswer(invocation -> {
                    normalized.set(invocation.getArgument(1));
                    return true;
                });

        Boolean result = hasher.verify(hash, password).await().indefinitely();

        assertTrue(result);
        assertWiped(password);
        assertWiped(normalized.get());

        verify(argon2).verify(eq(hash), any(char[].class));
    }

    @Test
    void verify_shouldReturnFalseAndWipePassword() {
        char[] password = "wrong-password".toCharArray();
        AtomicReference<char[]> normalized = new AtomicReference<>();
        String hash = "$argon2id$test";

        when(argon2.verify(eq(hash), any(char[].class)))
                .thenAnswer(invocation -> {
                    normalized.set(invocation.getArgument(1));
                    return false;
                });

        Boolean result = hasher.verify(hash, password).await().indefinitely();

        assertFalse(result);
        assertWiped(password);
        assertWiped(normalized.get());

        verify(argon2).verify(eq(hash), any(char[].class));
    }

    @Test
    void hash_shouldWipePasswordWhenArgon2Fails() {
        char[] password = "password123".toCharArray();
        AtomicReference<char[]> normalized = new AtomicReference<>();
        RuntimeException exception = new IllegalStateException("Argon2 failed");

        when(argon2.hash(anyInt(), anyInt(), anyInt(), any(char[].class), eq(StandardCharsets.UTF_8)))
                .thenAnswer(invocation -> {
                    normalized.set(invocation.getArgument(3));
                    throw exception;
                });

        RuntimeException result = assertThrows(
                RuntimeException.class,
                () -> hasher.hash(password).await().indefinitely()
        );

        assertSame(exception, result);
        assertWiped(password);
        assertWiped(normalized.get());
    }

    @Test
    void hash_shouldThrowServiceOverloadedExceptionWhenExecutorRejectsTask() {
        PasswordHasher rejectingHasher = new PasswordHasher(
                argon2, config, new RejectingExecutorService()
        );
        char[] password = "password123".toCharArray();

        assertThrows(
                ServiceOverloadedException.class,
                () -> rejectingHasher.hash(password).await().indefinitely()
        );

        assertWiped(password);

        verify(argon2, never()).hash(
                anyInt(), anyInt(), anyInt(), any(char[].class), eq(StandardCharsets.UTF_8)
        );
    }

    @Test
    void hashShouldRunOutsideEventLoop() {
        AtomicReference<String> threadName = new AtomicReference<>();

        when(argon2.hash(anyInt(), anyInt(), anyInt(), any(char[].class), eq(StandardCharsets.UTF_8)))
                .thenAnswer(invocation -> {
                    threadName.set(Thread.currentThread().getName());
                    return "$argon2id$test";
                });

        String result = hasher.hash("Password123!".toCharArray()).await().indefinitely();

        assertEquals("$argon2id$test", result);
        assertNotNull(threadName.get());
        assertFalse(threadName.get().startsWith("vert.x-eventloop-"));
    }

    @Test
    void hashShouldRespectConcurrencyLimit() throws InterruptedException {
        AtomicInteger active = new AtomicInteger();
        AtomicInteger maxActive = new AtomicInteger();
        CountDownLatch started = new CountDownLatch(CONCURRENCY_LIMIT);
        CountDownLatch release = new CountDownLatch(1);

        ExecutorService limitedExecutor = new ThreadPoolExecutor(
                CONCURRENCY_LIMIT,
                CONCURRENCY_LIMIT,
                0L,
                TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(8),
                new ThreadPoolExecutor.AbortPolicy()
        );

        PasswordHasher concurrentHasher = new PasswordHasher(argon2, config, limitedExecutor);

        when(argon2.hash(anyInt(), anyInt(), anyInt(), any(char[].class), eq(StandardCharsets.UTF_8)))
                .thenAnswer(invocation -> {
                    int current = active.incrementAndGet();
                    maxActive.accumulateAndGet(current, Math::max);
                    started.countDown();

                    try {
                        if (!release.await(5, TimeUnit.SECONDS)) {
                            throw new IllegalStateException("Timed out waiting for release");
                        }
                        return "$argon2id$test";
                    } finally {
                        active.decrementAndGet();
                    }
                });

        try {
            List<UniAssertSubscriber<String>> subscribers = java.util.stream.IntStream.range(0, 8)
                    .mapToObj(i -> concurrentHasher.hash(("Password" + i + "123!").toCharArray())
                            .subscribe().withSubscriber(UniAssertSubscriber.create()))
                    .toList();

            assertTrue(started.await(5, TimeUnit.SECONDS));
            assertEquals(CONCURRENCY_LIMIT, maxActive.get());

            release.countDown();

            subscribers.forEach(subscriber ->
                    subscriber.awaitItem().assertItem("$argon2id$test"));

            assertEquals(CONCURRENCY_LIMIT, maxActive.get());
        } finally {
            release.countDown();
            limitedExecutor.shutdownNow();
        }
    }

    @Test
    void hashShouldReturnServiceOverloadedWhenExecutorRejectsTask() {
        PasswordHasher rejectingHasher = new PasswordHasher(
                argon2, config, new RejectingExecutorService()
        );

        UniAssertSubscriber<String> subscriber = rejectingHasher.hash("Password123!".toCharArray())
                .subscribe().withSubscriber(UniAssertSubscriber.create());

        subscriber.awaitFailure()
                .assertFailedWith(ServiceOverloadedException.class);
    }

    private void assertWiped(char[] password) {
        assertNotNull(password);
        assertArrayEquals(new char[password.length], password);
    }

    private static class DirectExecutorService extends AbstractExecutorService {

        private boolean shutdown;

        @Override
        public void execute(Runnable command) {
            command.run();
        }

        @Override
        public void shutdown() {
            shutdown = true;
        }

        @Override
        public List<Runnable> shutdownNow() {
            shutdown = true;
            return List.of();
        }

        @Override
        public boolean isShutdown() {
            return shutdown;
        }

        @Override
        public boolean isTerminated() {
            return shutdown;
        }

        @Override
        public boolean awaitTermination(long timeout, TimeUnit unit) {
            return shutdown;
        }
    }

    private static class RejectingExecutorService extends DirectExecutorService {

        @Override
        public void execute(Runnable command) {
            throw new RejectedExecutionException("Executor is full");
        }
    }
}
