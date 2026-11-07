package ru.zeker.keymaster.service.key;

import io.vertx.core.Vertx;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import ru.zeker.keymaster.domain.key.GeneratedKey;
import ru.zeker.keymaster.domain.key.RsaKeyCodec;
import ru.zeker.keymaster.exception.ServiceOverloadedException;

import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SigningKeyGeneratorTest {

    private ExecutorService executor;

    @AfterEach
    void stopExecutor() {
        if (executor != null) {
            executor.shutdownNow();
        }
    }

    @Test
    void generatesKeyOffVertxEventLoop() throws Exception {
        AtomicReference<String> generationThread = new AtomicReference<>();

        executor = Executors.newSingleThreadExecutor(runnable -> new Thread(() -> {
            generationThread.set(Thread.currentThread().getName());
            runnable.run();
        }, "key-generation-test"));

        SigningKeyGenerator generator = new SigningKeyGenerator(executor);
        Vertx vertx = Vertx.vertx();

        try {
            CompletableFuture<GeneratedKey> result = new CompletableFuture<>();

            vertx.runOnContext(ignored -> {
                assertTrue(Vertx.currentContext().isEventLoopContext());
                generator.generate().subscribe().with(
                        result::complete,
                        result::completeExceptionally
                );
            });

            GeneratedKey key = result.get(30, TimeUnit.SECONDS);

            assertNotNull(generationThread.get());
            assertTrue(generationThread.get().startsWith("key-generation-test"),
                    () -> "unexpected generation thread: " + generationThread.get());
            assertFalse(generationThread.get().startsWith("vert.x-eventloop-"),
                    () -> "RSA generation ran on the event loop: " + generationThread.get());

            RSAPublicKey publicKey = (RSAPublicKey) RsaKeyCodec.publicFromSpki(key.publicSpki());
            assertEquals(RsaKeyCodec.thumbprint(publicKey), key.kid());
            assertEquals(43, key.kid().length());
            assertNotNull(RsaKeyCodec.privateFromPkcs8(key.privatePkcs8()));
        } finally {
            vertx.close().toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
        }
    }

    @Test
    void queueOverflowBecomesServiceOverloaded() throws Exception {
        CountDownLatch workerStarted = new CountDownLatch(1);
        CountDownLatch releaseWorker = new CountDownLatch(1);

        executor = new ThreadPoolExecutor(
                1,
                1,
                0L,
                TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(1),
                runnable -> new Thread(runnable, "key-generation-overflow-"),
                new ThreadPoolExecutor.AbortPolicy()
        );

        executor.execute(() -> {
            workerStarted.countDown();
            try {
                releaseWorker.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });

        assertTrue(workerStarted.await(5, TimeUnit.SECONDS));
        executor.execute(() -> {
            // occupies the single queue slot
        });

        SigningKeyGenerator generator = new SigningKeyGenerator(executor);

        try {
            assertThrows(ServiceOverloadedException.class,
                    () -> generator.generate().await().indefinitely());
        } finally {
            releaseWorker.countDown();
        }
    }
}
