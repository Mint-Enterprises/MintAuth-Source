// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import static org.junit.Assert.*;

import com.google.gson.JsonObject;

import org.junit.Test;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

public class MultiplayerAccessTest {
    private static final String SECRET = "SYNTHETIC_SSID_NEVER_LOG";

    private static String attributes(boolean enabled) {
        return "{\"privileges\":{\"multiplayerServer\":{\"enabled\":"
                + enabled
                + "}},\"bannedScopes\":{}}";
    }

    private static HttpURLConnection response(String url, int status, String body)
            throws Exception {
        return new HttpURLConnection(new URL(url)) {
            public void connect() {}

            public void disconnect() {}

            public boolean usingProxy() {
                return false;
            }

            public int getResponseCode() {
                return status;
            }

            public InputStream getInputStream() {
                return new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8));
            }

            public InputStream getErrorStream() {
                return getInputStream();
            }

            public OutputStream getOutputStream() {
                return new ByteArrayOutputStream();
            }
        };
    }

    @Test
    public void distinguishesDisabledMultiplayerFromInvalidTokensAndBans() {
        MultiplayerAccess disabled =
                MultiplayerAccess.parse(Json.object(attributes(false), 4096), 100);
        assertEquals(MultiplayerAccess.DISABLED, disabled);
        assertTrue(disabled.restriction().contains("Xbox privacy"));
        assertTrue(disabled.restriction().contains("Singleplayer"));
        assertEquals(
                MultiplayerAccess.ALLOWED,
                MultiplayerAccess.parse(Json.object(attributes(true), 4096), 100));
        assertEquals(MultiplayerAccess.UNKNOWN, MultiplayerAccess.parse(new JsonObject(), 100));
        assertEquals(
                MultiplayerAccess.UNKNOWN,
                MultiplayerAccess.parse(
                        Json.object(
                                "{\"privileges\":{\"multiplayerServer\":{\"enabled\":\"false\"}}}",
                                4096),
                        100));
        assertEquals(
                MultiplayerAccess.BANNED,
                MultiplayerAccess.parse(
                        Json.object(
                                "{\"bannedScopes\":{\"MULTIPLAYER\":{\"expires\":null}}}", 4096),
                        100));
        JsonObject timed = Json.object(attributes(true), 4096);
        timed.add("bannedScopes", Json.object("{\"MULTIPLAYER\":{\"expires\":200}}", 4096));
        assertEquals(MultiplayerAccess.BANNED, MultiplayerAccess.parse(timed, 100));
        assertEquals(MultiplayerAccess.ALLOWED, MultiplayerAccess.parse(timed, 300));
        timed.add(
                "bannedScopes",
                Json.object("{\"MULTIPLAYER\":{\"expires\":\"1970-01-01T00:00:00.200Z\"}}", 4096));
        assertEquals(MultiplayerAccess.BANNED, MultiplayerAccess.parse(timed, 100));
        assertEquals(MultiplayerAccess.ALLOWED, MultiplayerAccess.parse(timed, 300));
    }

    @Test
    public void fixedEndpointLogsOnlyHttpStatusAndPermissionEnum() throws Exception {
        List<String> lines = new ArrayList<>();
        AtomicReference<HttpURLConnection> request = new AtomicReference<>();
        ProtocolClient api =
                new ProtocolClient(
                        (url, method) -> {
                            assertEquals(
                                    "https://api.minecraftservices.com/player/attributes", url);
                            assertEquals("GET", method);
                            try {
                                HttpURLConnection connection =
                                        response(url, 200, attributes(false));
                                request.set(connection);
                                return connection;
                            } catch (Exception error) {
                                throw new IOException(error);
                            }
                        });
        api.setDiagnostics(new FlowDiagnostics(lines::add, lines::add));
        assertEquals(MultiplayerAccess.DISABLED, api.multiplayerAccess(SECRET));
        assertFalse(request.get().getInstanceFollowRedirects());
        assertEquals("Bearer " + SECRET, request.get().getRequestProperty("Authorization"));
        String log = String.join("\n", lines);
        assertTrue(log.contains("multiplayer=DISABLED"));
        assertTrue(log.contains("http_status=200"));
        assertFalse(log.contains(SECRET));
        assertFalse(log.contains("Authorization"));
        assertFalse(log.contains("bannedScopes"));
    }

    @Test
    public void onlyAnExplicit401IsTokenRejectionAndResponsesAreBounded() throws Exception {
        for (int status : new int[] {301, 302, 403, 429, 500, 503, 401}) {
            ProtocolClient api =
                    new ProtocolClient(
                            (url, method) -> {
                                try {
                                    return response(url, status, "{}");
                                } catch (Exception error) {
                                    throw new IOException(error);
                                }
                            });
            try {
                api.multiplayerAccess(SECRET);
                fail();
            } catch (IOException failure) {
                assertEquals(status == 401, failure instanceof ProtocolClient.ApiException);
                if (status == 401)
                    assertEquals(
                            "EXTERNAL_TOKEN_REJECTED",
                            ((ProtocolClient.ApiException) failure).code);
            }
        }
        ProtocolClient large =
                new ProtocolClient(
                        (url, method) -> {
                            try {
                                return response(
                                        url, 200, String.join("", Collections.nCopies(40000, "x")));
                            } catch (Exception error) {
                                throw new IOException(error);
                            }
                        });
        try {
            large.multiplayerAccess(SECRET);
            fail();
        } catch (IOException expected) {
            assertEquals("RESPONSE_LIMIT", expected.getMessage());
        }
    }

    private static ProtocolClient protocol(
            AtomicBoolean enabled, AtomicBoolean outage, AtomicInteger providers) {
        return new ProtocolClient(
                (url, method) -> {
                    if (url.contains("/sessions")) providers.incrementAndGet();
                    try {
                        if (url.endsWith("/player/attributes"))
                            return response(
                                    url, outage.get() ? 503 : 200, attributes(enabled.get()));
                        return response(
                                url,
                                200,
                                "{\"id\":\""
                                        + PreparationLifecycleTest.UUID
                                        + "\",\"name\":\"SyntheticUser\"}");
                    } catch (Exception error) {
                        throw new IOException(error);
                    }
                });
    }

    @Test
    public void disabledAccountStillSelectsForSingleplayerAndCanRetryAfterPrivacyChange()
            throws Exception {
        AtomicBoolean enabled = new AtomicBoolean(), outage = new AtomicBoolean();
        AtomicInteger providers = new AtomicInteger();
        PreparationLifecycleTest.Bridge bridge = new PreparationLifecycleTest.Bridge();
        try (PreparationLifecycleTest.Fixture fixture =
                new PreparationLifecycleTest.Fixture(
                        bridge, protocol(enabled, outage, providers), false)) {
            fixture.runtime.select(PreparationLifecycleTest.ID, false);
            Runnable apply = bridge.callbacks.poll(5, TimeUnit.SECONDS);
            assertNotNull(apply);
            apply.run();
            assertEquals(
                    AccountPreparation.Phase.READY, fixture.runtime.preparation().snapshot().phase);
            assertEquals(1, bridge.installed.get());
            assertTrue(fixture.runtime.allowJoin());
            assertNotNull(fixture.runtime.multiplayerIssue());
            assertFalse(fixture.runtime.checkBeforeServerJoin(bridge.fingerprint));
            assertTrue(fixture.runtime.joinFailureMessage().contains("Xbox privacy"));
            assertEquals(
                    "AVAILABLE",
                    Json.string(
                            fixture.vault
                                    .read()
                                    .getAsJsonObject("accounts")
                                    .getAsJsonObject(PreparationLifecycleTest.ID),
                            "status"));
            outage.set(true);
            assertFalse(fixture.runtime.checkBeforeServerJoin(bridge.fingerprint));
            assertNotNull(fixture.runtime.multiplayerIssue());
            outage.set(false);
            enabled.set(true);
            assertTrue(fixture.runtime.checkBeforeServerJoin(bridge.fingerprint));
            assertNull(fixture.runtime.multiplayerIssue());
            assertEquals(0, providers.get());
            fixture.runtime.restoreLauncher();
            Runnable restore = bridge.callbacks.poll(5, TimeUnit.SECONDS);
            assertNotNull(restore);
            restore.run();
            assertNull(fixture.runtime.multiplayerIssue());
        }
    }

    @Test
    public void latePermissionReplyCannotOverwriteLauncherRestoration() throws Exception {
        AtomicBoolean block = new AtomicBoolean();
        CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
        ProtocolClient api =
                new ProtocolClient(
                        (url, method) -> {
                            try {
                                if (url.endsWith("/player/attributes")) {
                                    if (block.get()) {
                                        entered.countDown();
                                        if (!release.await(5, TimeUnit.SECONDS))
                                            throw new IOException("Synthetic timeout");
                                    }
                                    return response(url, 200, attributes(block.get()));
                                }
                                return response(
                                        url,
                                        200,
                                        "{\"id\":\""
                                                + PreparationLifecycleTest.UUID
                                                + "\",\"name\":\"SyntheticUser\"}");
                            } catch (Exception error) {
                                throw new IOException(error);
                            }
                        });
        PreparationLifecycleTest.Bridge bridge = new PreparationLifecycleTest.Bridge();
        ExecutorService worker = Executors.newSingleThreadExecutor();
        try (PreparationLifecycleTest.Fixture fixture =
                new PreparationLifecycleTest.Fixture(bridge, api, false)) {
            fixture.runtime.select(PreparationLifecycleTest.ID, false);
            Runnable apply = bridge.callbacks.poll(5, TimeUnit.SECONDS);
            assertNotNull(apply);
            apply.run();
            block.set(true);
            String fingerprint = bridge.fingerprint;
            Future<Boolean> join =
                    worker.submit(() -> fixture.runtime.checkBeforeServerJoin(fingerprint));
            assertTrue(entered.await(5, TimeUnit.SECONDS));
            fixture.runtime.restoreLauncher();
            Runnable restore = bridge.callbacks.poll(5, TimeUnit.SECONDS);
            assertNotNull(restore);
            restore.run();
            release.countDown();
            assertFalse(join.get(5, TimeUnit.SECONDS));
            assertNull(fixture.runtime.activeId());
            assertNull(fixture.runtime.multiplayerIssue());
            assertEquals(1, bridge.installed.get());
        } finally {
            release.countDown();
            worker.shutdownNow();
        }
    }

    @Test
    public void privacyRestrictionNeverShortCircuitsCanonicalRevocationChecks() throws Exception {
        AtomicBoolean managed = new AtomicBoolean(false);
        ProtocolClient api =
                new ProtocolClient(
                        (url, method) -> {
                            try {
                                if (url.endsWith("/player/attributes"))
                                    return response(url, 200, attributes(false));
                                if (url.endsWith("/authorization")) {
                                    managed.set(true);
                                    return response(url, 401, "{\"code\":\"MINTAUTH_REVOKED\"}");
                                }
                                return response(
                                        url,
                                        200,
                                        "{\"id\":\""
                                                + PreparationLifecycleTest.UUID
                                                + "\",\"name\":\"SyntheticUser\"}");
                            } catch (Exception error) {
                                throw new IOException(error);
                            }
                        });
        List<String> logs = new ArrayList<>();
        PreparationLifecycleTest.Bridge bridge =
                new PreparationLifecycleTest.Bridge() {
                    public void logDiagnostic(String line) {
                        logs.add(line);
                    }

                    public void logFailureDiagnostic(String line) {
                        logs.add(line);
                    }
                };
        try (PreparationLifecycleTest.Fixture fixture =
                new PreparationLifecycleTest.Fixture(bridge, api, false)) {
            fixture.runtime.select(PreparationLifecycleTest.ID, false);
            Runnable apply = bridge.callbacks.poll(5, TimeUnit.SECONDS);
            assertNotNull(apply);
            apply.run();
            fixture.vault.update(
                    data -> {
                        JsonObject entry =
                                data.getAsJsonObject("accounts")
                                        .getAsJsonObject(PreparationLifecycleTest.ID);
                        entry.addProperty("source", "MANAGED");
                        entry.add("context", Json.obj("accountId", PreparationLifecycleTest.ID));
                        JsonObject auth = Json.obj("access_token", SECRET);
                        auth.addProperty("device_id", "synthetic-device");
                        data.add("authorization", auth);
                        return null;
                    });
            assertFalse(fixture.runtime.checkBeforeAuthentication(bridge.fingerprint));
            assertTrue(String.join("\n", logs), managed.get());
            assertNull(fixture.runtime.activeId());
        }
    }
}
