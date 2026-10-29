// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import static org.junit.Assert.*;

import com.google.gson.JsonObject;

import org.junit.Test;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;

public class PreparationLifecycleTest {
    static final String ID = "synthetic-account";
    static final String UUID = "11111111111111111111111111111111";

    static HttpURLConnection response(String url, String json) throws IOException {
        return new HttpURLConnection(new URL(url)) {
            public void connect() {}

            public void disconnect() {}

            public boolean usingProxy() {
                return false;
            }

            public int getResponseCode() {
                return 200;
            }

            public InputStream getInputStream() {
                return new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8));
            }

            public OutputStream getOutputStream() {
                return new ByteArrayOutputStream();
            }
        };
    }

    static class Bridge implements GameBridge {
        final BlockingQueue<Runnable> callbacks = new LinkedBlockingQueue<>();
        final AtomicInteger installed = new AtomicInteger();
        volatile String fingerprint;

        public void onClient(Runnable action) {
            callbacks.add(action);
        }

        public boolean worldOpen() {
            return false;
        }

        public String currentFingerprint() {
            return fingerprint;
        }

        public void install(Identity identity) {
            installed.incrementAndGet();
            fingerprint = identity.fingerprint();
        }

        public void restoreLauncher() {
            fingerprint = null;
        }

        public void leaveWorld(String reason, Runnable after) {
            after.run();
        }

        public void connect(String destination) {
            fail("No connection is permitted in this test");
        }

        public void logDiagnostic(String line) {}

        public Object prepare(Identity identity) throws Exception {
            return null;
        }
    }

    static class Fixture implements AutoCloseable {
        final Path root = Files.createTempDirectory("mintauth-preparation-test");
        final Vault vault = new Vault(root, new SecurityTest.MemoryStore());
        final MintAuthRuntime runtime;

        Fixture(Bridge bridge, ProtocolClient protocol, boolean managed) throws Exception {
            vault.unlock(null, false);
            JsonObject account = Json.obj("id", ID);
            account.addProperty("ign", "SyntheticUser");
            account.addProperty("uuid", UUID);
            account.addProperty("kind", managed ? "OWNED" : "EXTERNAL");
            account.addProperty("source", managed ? "MANAGED" : "LOCAL");
            account.addProperty("revision", 1);
            account.addProperty("status", "AVAILABLE");
            if (managed) account.add("context", Json.obj("accountId", ID));
            else account.addProperty("ssid", "synthetic-test-token-never-sent-to-network");
            vault.update(
                    data -> {
                        JsonObject accounts = new JsonObject();
                        accounts.add(ID, account);
                        data.add("accounts", accounts);
                        if (managed) {
                            JsonObject auth =
                                    Json.obj("access_token", "synthetic-test-authorization");
                            auth.addProperty("device_id", "synthetic-device");
                            data.add("authorization", auth);
                        }
                        return null;
                    });
            runtime = new MintAuthRuntime(bridge, root, vault, protocol, false);
        }

        public void close() {
            runtime.close();
        }
    }

    static ProtocolClient localProfile() {
        return new ProtocolClient(
                (url, method) -> {
                    if (url.equals("https://api.minecraftservices.com/player/attributes"))
                        return PreparationLifecycleTest.response(
                                url,
                                "{\"privileges\":{\"multiplayerServer\":{\"enabled\":true}},\"bannedScopes\":{}}");
                    assertEquals("https://api.minecraftservices.com/minecraft/profile", url);
                    return response(url, "{\"id\":\"" + UUID + "\",\"name\":\"SyntheticUser\"}");
                });
    }

    static void await(BooleanSupplier condition) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) fail("Timed out waiting for test lifecycle state");
            Thread.sleep(5);
        }
    }

    @Test
    public void preparationFailureIsTerminalWithoutWaitingForOtherWork() throws Exception {
        Bridge bridge =
                new Bridge() {
                    public Object prepare(Identity identity) throws Exception {
                        throw new SocketTimeoutException(
                                "synthetic-sensitive-error-must-not-appear");
                    }
                };
        try (Fixture fixture = new Fixture(bridge, localProfile(), false)) {
            fixture.runtime.select(ID, false);
            AccountPreparation attempt = fixture.runtime.preparation();
            await(() -> attempt.snapshot().phase == AccountPreparation.Phase.FAILED);
            assertTrue(attempt.snapshot().phase.terminal());
            assertTrue(attempt.snapshot().message.contains("timed out"));
            assertFalse(attempt.snapshot().message.contains("synthetic-sensitive"));
            assertEquals(0, bridge.installed.get());
            assertNull(fixture.runtime.activeId());
        }
    }

    @Test
    public void cancelThenRetryIgnoresAnOldNetworkFailure() throws Exception {
        CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
        AtomicInteger calls = new AtomicInteger();
        Bridge bridge =
                new Bridge() {
                    public Object prepare(Identity identity) throws Exception {
                        if (calls.incrementAndGet() == 1) {
                            entered.countDown();
                            assertTrue(release.await(5, TimeUnit.SECONDS));
                            throw new SocketTimeoutException("synthetic-old-timeout");
                        }
                        return null;
                    }
                };
        try (Fixture fixture = new Fixture(bridge, localProfile(), false)) {
            fixture.runtime.select(ID, false);
            AccountPreparation old = fixture.runtime.preparation();
            assertTrue(entered.await(5, TimeUnit.SECONDS));
            fixture.runtime.cancelPreparation();
            fixture.runtime.select(ID, false);
            AccountPreparation retry = fixture.runtime.preparation();
            assertNotSame(old, retry);
            assertEquals(AccountPreparation.Phase.QUEUED, retry.snapshot().phase);
            assertFalse(retry.snapshot().message.toLowerCase().contains("cancel"));
            release.countDown();
            await(() -> retry.snapshot().phase == AccountPreparation.Phase.APPLYING);
            assertEquals(AccountPreparation.Phase.CANCELLED, old.snapshot().phase);
            assertFalse(retry.snapshot().message.contains("timed out"));
            bridge.callbacks.take().run();
            assertEquals(AccountPreparation.Phase.READY, retry.snapshot().phase);
            assertEquals(1, bridge.installed.get());
        } finally {
            release.countDown();
        }
    }

    @Test
    public void cancellationFencesLateClientInstallation() throws Exception {
        Bridge bridge = new Bridge();
        try (Fixture fixture = new Fixture(bridge, localProfile(), false)) {
            fixture.runtime.select(ID, false);
            AccountPreparation old = fixture.runtime.preparation();
            Runnable oldInstall = bridge.callbacks.poll(5, TimeUnit.SECONDS);
            assertNotNull(oldInstall);
            assertEquals(AccountPreparation.Phase.APPLYING, old.snapshot().phase);
            fixture.runtime.cancelPreparation();
            fixture.runtime.select(ID, false);
            AccountPreparation retry = fixture.runtime.preparation();
            oldInstall.run();
            assertEquals(0, bridge.installed.get());
            assertNull(fixture.runtime.activeId());
            Runnable currentInstall = bridge.callbacks.poll(5, TimeUnit.SECONDS);
            assertNotNull(currentInstall);
            currentInstall.run();
            assertEquals(AccountPreparation.Phase.READY, retry.snapshot().phase);
            assertEquals(1, bridge.installed.get());
            assertEquals(AccountPreparation.Phase.CANCELLED, old.snapshot().phase);
        }
    }

    @Test
    public void cancelledAuthorityResponseCannotDispatchProviderWork() throws Exception {
        CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
        AtomicInteger sessions = new AtomicInteger();
        ProtocolClient protocol =
                new ProtocolClient(
                        (url, method) -> {
                            if (url.endsWith("/sessions")) sessions.incrementAndGet();
                            assertTrue(url.endsWith("/authorization"));
                            return new HttpURLConnection(new URL(url)) {
                                public void connect() {}

                                public void disconnect() {}

                                public boolean usingProxy() {
                                    return false;
                                }

                                public OutputStream getOutputStream() {
                                    return new ByteArrayOutputStream();
                                }

                                public int getResponseCode() throws IOException {
                                    entered.countDown();
                                    try {
                                        if (!release.await(5, TimeUnit.SECONDS))
                                            throw new IOException("test-timeout");
                                    } catch (InterruptedException error) {
                                        throw new IOException(error);
                                    }
                                    return 200;
                                }

                                public InputStream getInputStream() {
                                    return new ByteArrayInputStream(
                                            "{\"credentialVersionId\":\"synthetic\",\"ownershipEpoch\":1,\"generationId\":\"synthetic\",\"eligibilityRevision\":1,\"context\":{\"accountId\":\"synthetic-account\"},\"offlineUntil\":null,\"checkedAt\":null,\"transferPending\":false}"
                                                    .getBytes(StandardCharsets.UTF_8));
                                }
                            };
                        });
        Bridge bridge = new Bridge();
        try (Fixture fixture = new Fixture(bridge, protocol, true)) {
            fixture.runtime.select(ID, false);
            AccountPreparation attempt = fixture.runtime.preparation();
            long ticket = fixture.runtime.submittedOperation();
            assertTrue(entered.await(5, TimeUnit.SECONDS));
            fixture.runtime.cancelPreparation();
            release.countDown();
            await(() -> fixture.runtime.completedOperation(ticket) != null);
            assertEquals(AccountPreparation.Phase.CANCELLED, attempt.snapshot().phase);
            assertEquals(0, sessions.get());
            assertEquals(0, bridge.installed.get());
        } finally {
            release.countDown();
        }
    }

    @Test
    public void managedConnectionFailureDoesNotRemainLoadingOrReuseCancelledCopy()
            throws Exception {
        Bridge bridge = new Bridge();
        AtomicInteger connections = new AtomicInteger();
        ProtocolClient protocol =
                new ProtocolClient(
                        (url, method) -> {
                            assertTrue(url.endsWith("/authorization"));
                            connections.incrementAndGet();
                            throw new ConnectException("synthetic-private-network-detail");
                        });
        try (Fixture fixture = new Fixture(bridge, protocol, true)) {
            fixture.runtime.select(ID, false);
            AccountPreparation first = fixture.runtime.preparation();
            await(() -> first.snapshot().phase == AccountPreparation.Phase.FAILED);
            assertTrue(first.snapshot().phase.terminal());
            assertTrue(first.snapshot().message.contains("Could not reach AutoMint"));
            assertFalse(first.snapshot().message.contains("private-network"));
            fixture.runtime.cancelPreparation();
            fixture.runtime.select(ID, false);
            AccountPreparation retry = fixture.runtime.preparation();
            await(() -> retry.snapshot().phase == AccountPreparation.Phase.FAILED);
            assertNotSame(first, retry);
            assertFalse(retry.snapshot().message.toLowerCase().contains("cancel"));
            assertEquals(2, connections.get());
            assertEquals(0, bridge.installed.get());
        }
    }

    @Test
    public void playingAccountCannotBeSelectedAgainUntilLauncherRestoration() throws Exception {
        Bridge bridge = new Bridge();
        try (Fixture fixture = new Fixture(bridge, localProfile(), false)) {
            assertNull(fixture.runtime.playingAccountId());
            fixture.runtime.select(ID, false);
            Runnable install = bridge.callbacks.poll(5, TimeUnit.SECONDS);
            assertNotNull(install);
            install.run();
            assertEquals(ID, fixture.runtime.playingAccountId());
            long submitted = fixture.runtime.submittedOperation();
            AccountPreparation original = fixture.runtime.preparation();
            fixture.runtime.select(ID, false);
            assertEquals(submitted, fixture.runtime.submittedOperation());
            assertSame(original, fixture.runtime.preparation());
            assertEquals(1, bridge.installed.get());

            fixture.runtime.restoreLauncher();
            Runnable restore = bridge.callbacks.poll(5, TimeUnit.SECONDS);
            assertNotNull(restore);
            restore.run();
            assertNull(fixture.runtime.playingAccountId());
            fixture.runtime.select(ID, false);
            assertNotSame(original, fixture.runtime.preparation());
            Runnable selectAgain = bridge.callbacks.poll(5, TimeUnit.SECONDS);
            assertNotNull(selectAgain);
            selectAgain.run();
            assertEquals(ID, fixture.runtime.playingAccountId());
            assertEquals(2, bridge.installed.get());
        }
    }

    @Test
    public void switchingIdentityOutsideMintUnlocksBeforeMaintenanceClearsTheOldId()
            throws Exception {
        Bridge bridge = new Bridge();
        try (Fixture fixture = new Fixture(bridge, localProfile(), false)) {
            fixture.runtime.select(ID, false);
            Runnable install = bridge.callbacks.poll(5, TimeUnit.SECONDS);
            assertNotNull(install);
            install.run();
            assertEquals(ID, fixture.runtime.playingAccountId());
            bridge.restoreLauncher();
            assertEquals(ID, fixture.runtime.activeId());
            assertNull(fixture.runtime.playingAccountId());
            AccountPreparation previous = fixture.runtime.preparation();
            fixture.runtime.select(ID, false);
            assertNotSame(previous, fixture.runtime.preparation());
            Runnable selectAgain = bridge.callbacks.poll(5, TimeUnit.SECONDS);
            assertNotNull(selectAgain);
            selectAgain.run();
            assertEquals(ID, fixture.runtime.playingAccountId());
        }
    }

    @Test
    public void errorAndMoveOutcomesCannotBeOverwrittenByLateProgress() {
        for (AccountPreparation.Phase phase :
                new AccountPreparation.Phase[] {
                    AccountPreparation.Phase.FAILED, AccountPreparation.Phase.MOVE
                }) {
            AccountPreparation attempt = new AccountPreparation(1, ID);
            attempt.update(phase, "original outcome");
            attempt.update(AccountPreparation.Phase.PREPARING, "stale progress");
            assertEquals(phase, attempt.snapshot().phase);
            assertEquals("original outcome", attempt.snapshot().message);
        }
    }

    @Test
    public void guidedFailuresKeepTheirOwnMessages() {
        MintAuthRuntime.UiOperations operations = new MintAuthRuntime.UiOperations();
        operations.finish(1, false, "first failure");
        operations.finish(2, true, "unrelated success");
        assertEquals("first failure", operations.get(1).message);
        assertFalse(operations.get(1).succeeded);
    }
}
