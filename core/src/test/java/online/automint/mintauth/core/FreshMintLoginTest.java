// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import static org.junit.Assert.*;

import com.google.gson.*;

import org.junit.Test;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.*;
import javax.crypto.spec.*;

public class FreshMintLoginTest {
    static final String OLD = "synthetic-managed-cached-ssid";
    static final String FRESH = "synthetic-managed-fresh-ssid";

    static class Server implements ProtocolClient.Connections {
        final String accountId;
        final AtomicInteger sessions = new AtomicInteger(), authorizations = new AtomicInteger();
        boolean unchanged, offline, missingCheck, bumpSettingsAfterDelivery, bumpOwnerAfterDelivery, bumpCredentialsAfterDelivery, sessionRejected, multiplayerDisabled;
        int sessionStatus = 200;

        Server(String accountId) {
            this.accountId = accountId;
        }

        public HttpURLConnection open(String endpoint, String method) throws IOException {
            if (offline && endpoint.endsWith("/authorization"))
                throw new ConnectException("synthetic-private-network-details");
            return new HttpURLConnection(new URL(endpoint)) {
                final ByteArrayOutputStream request = new ByteArrayOutputStream();

                public void connect() {}

                public void disconnect() {}

                public boolean usingProxy() {
                    return false;
                }

                public OutputStream getOutputStream() {
                    return request;
                }

                public int getResponseCode() {
                    if (endpoint.endsWith("/sessions")) {
                        sessions.incrementAndGet();
                        return sessionStatus;
                    }
                    return 200;
                }

                public InputStream getErrorStream() {
                    return bytes("{\"code\":\"SESSION_REQUEST_COOLDOWN\"}");
                }

                public InputStream getInputStream() throws IOException {
                    try {
                        if (endpoint.endsWith("/authorization")) {
                            authorizations.incrementAndGet();
                            JsonObject authority = Json.obj("credentialVersionId", bumpCredentialsAfterDelivery && authorizations.get() > 1 ? "new-version" : "version");
                            authority.addProperty("ownershipEpoch", bumpOwnerAfterDelivery && authorizations.get() > 1 ? 2 : 1);
                            authority.addProperty("generationId", "generation");
                            authority.addProperty("eligibilityRevision", 1);
                            authority.addProperty("transferPending", false);
                            authority.addProperty("sessionRevision", 0);
                            authority.addProperty("sessionRejected", sessionRejected);
                            authority.addProperty("multiplayer", !multiplayerDisabled);
                            authority.addProperty("multiplayerRevision", bumpSettingsAfterDelivery && authorizations.get() > 1 ? 1 : 0);
                            authority.addProperty(
                                    "offlineUntil", Instant.now().plusSeconds(900).toString());
                            authority.addProperty("checkedAt", Instant.now().toString());
                            JsonObject context = Json.obj("kind", "INVENTORY");
                            context.addProperty("accountId", accountId);
                            authority.add("context", context);
                            return bytes(Json.GSON.toJson(authority));
                        }
                        if (endpoint.endsWith("/sessions")) {
                            JsonObject body =
                                    Json.object(
                                            new String(
                                                    request.toByteArray(), StandardCharsets.UTF_8),
                                            16384);
                            assertEquals("request", Json.string(body, "action"));
                            assertEquals(
                                    accountId,
                                    Json.string(body.getAsJsonObject("context"), "accountId"));
                            JsonObject result = Json.obj("id", "synthetic-request");
                            result.addProperty("state", "READY");
                            result.addProperty("bindingDealId", "mintauth-synthetic-device");
                            result.addProperty("credentialVersionId", "version");
                            result.addProperty(
                                    "outputCiphertext",
                                    seal(
                                            body.getAsJsonObject("publicKey"),
                                            unchanged ? OLD : FRESH,
                                            missingCheck));
                            JsonObject response = new JsonObject();
                            response.add("result", result);
                            return bytes(Json.GSON.toJson(response));
                        }
                        if (endpoint.endsWith("/player/attributes"))
                            return bytes(
                                    "{\"privileges\":{\"multiplayerServer\":{\"enabled\":true}}}");
                        assertEquals(
                                "https://api.minecraftservices.com/minecraft/profile", endpoint);
                        return bytes(
                                "{\"id\":\""
                                        + PreparationLifecycleTest.UUID
                                        + "\",\"name\":\"SyntheticUser\"}");
                    } catch (Exception error) {
                        throw new IOException(error);
                    }
                }
            };
        }
    }

    static InputStream bytes(String value) {
        return new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8));
    }

    static String seal(JsonObject jwk, String token, boolean missingCheck) throws Exception {
        PublicKey rsa =
                KeyFactory.getInstance("RSA")
                        .generatePublic(
                                new RSAPublicKeySpec(
                                        new java.math.BigInteger(
                                                1, Crypto.unb64(Json.string(jwk, "n"))),
                                        new java.math.BigInteger(
                                                1, Crypto.unb64(Json.string(jwk, "e")))));
        JsonObject binding = new JsonObject();
        binding.addProperty("v", 1);
        binding.addProperty("dealId", "mintauth-synthetic-device");
        binding.addProperty("commandId", "synthetic-request");
        binding.addProperty("actorId", "synthetic-user");
        binding.addProperty("purpose", "DELIVERY");
        binding.addProperty("credentialVersionId", "version");
        binding.add("reportId", JsonNull.INSTANCE);
        JsonObject header = Json.obj("alg", "RSA-OAEP-256");
        header.addProperty("enc", "A256GCM");
        header.addProperty("typ", "automint-autosec+jwe");
        header.addProperty("am", Json.GSON.toJson(binding));
        String encoded = Crypto.b64(Json.GSON.toJson(header).getBytes(StandardCharsets.UTF_8));
        JsonObject payload = Json.obj("uuid", PreparationLifecycleTest.UUID);
        payload.addProperty("ign", "SyntheticUser");
        payload.addProperty("ssid", token);
        payload.addProperty("sessionRevision", 0);
        payload.addProperty("multiplayerRevision", 0);
        payload.addProperty("deviceId", "synthetic-device");
        payload.addProperty("vaultGeneration", "synthetic-generation");
        payload.addProperty("providerCheckedAt", missingCheck ? null : Instant.now().toString());
        payload.add("knownExpiresAt", JsonNull.INSTANCE);
        byte[] key = Crypto.random(32), iv = Crypto.random(12);
        Cipher wrap = Cipher.getInstance("RSA/ECB/OAEPPadding");
        wrap.init(
                Cipher.ENCRYPT_MODE,
                rsa,
                new OAEPParameterSpec(
                        "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        aes.updateAAD(encoded.getBytes(StandardCharsets.US_ASCII));
        byte[] encrypted = aes.doFinal(Json.GSON.toJson(payload).getBytes(StandardCharsets.UTF_8));
        return encoded
                + "."
                + Crypto.b64(wrap.doFinal(key))
                + "."
                + Crypto.b64(iv)
                + "."
                + Crypto.b64(Arrays.copyOf(encrypted, encrypted.length - 16))
                + "."
                + Crypto.b64(
                        Arrays.copyOfRange(encrypted, encrypted.length - 16, encrypted.length));
    }

    static void cached(PreparationLifecycleTest.Fixture f) throws Exception {
        f.vault.update(
                data -> {
                    JsonObject entry =
                            data.getAsJsonObject("accounts")
                                    .getAsJsonObject(PreparationLifecycleTest.ID);
                    entry.addProperty("ssid", OLD);
                    entry.addProperty("authorityStamp", "version/1/\"generation\"/1/0");
                    entry.addProperty("tokenCheckedAt", Instant.now().toString());
                    entry.addProperty("checkedAt", Instant.now().toString());
                    entry.addProperty("offlineUntil", Instant.now().plusSeconds(900).toString());
                    JsonObject auth = data.getAsJsonObject("authorization");
                    auth.addProperty("subject", "synthetic-user");
                    auth.addProperty("vault_generation", "synthetic-generation");
                    return null;
                });
    }

    @Test
    public void explicitLoginRequestsTheSharedCurrentSessionWithoutReconnect()
            throws Exception {
        Server server = new Server(PreparationLifecycleTest.ID);
        PreparationLifecycleTest.Bridge bridge = new PreparationLifecycleTest.Bridge();
        try (PreparationLifecycleTest.Fixture f =
                new PreparationLifecycleTest.Fixture(bridge, new ProtocolClient(server), true)) {
            cached(f);
            f.runtime.rememberDestination("synthetic.example");
            f.runtime.select(PreparationLifecycleTest.ID, false);
            Runnable apply = bridge.callbacks.poll(10, TimeUnit.SECONDS);
            assertNotNull(apply);
            assertEquals(1, server.sessions.get());
            assertEquals(2, server.authorizations.get());
            apply.run();
            assertEquals(AccountPreparation.Phase.READY, f.runtime.preparation().snapshot().phase);
            assertEquals(
                    PreparationLifecycleTest.UUID + ":" + Crypto.tokenHash(FRESH),
                    bridge.fingerprint);
            assertNull(bridge.callbacks.poll(100, TimeUnit.MILLISECONDS));
        }
    }

    @Test
    public void backgroundPreparationKeepsExistingFreshnessPolicy() throws Exception {
        Server server = new Server(PreparationLifecycleTest.ID);
        PreparationLifecycleTest.Bridge bridge = new PreparationLifecycleTest.Bridge();
        try (PreparationLifecycleTest.Fixture f =
                new PreparationLifecycleTest.Fixture(bridge, new ProtocolClient(server), true)) {
            cached(f);
            java.lang.reflect.Method prepare =
                    MintAuthRuntime.class.getDeclaredMethod(
                            "prepare",
                            String.class,
                            boolean.class,
                            boolean.class,
                            long.class,
                            boolean.class);
            prepare.setAccessible(true);
            prepare.invoke(f.runtime, PreparationLifecycleTest.ID, false, false, 0L, false);
            assertEquals(0, server.sessions.get());
            assertEquals(0, bridge.installed.get());
        }
    }

    @Test
    public void unchangedSharedSessionIsPlayable() throws Exception {
        Server server = new Server(PreparationLifecycleTest.ID);
        server.unchanged = true;
        PreparationLifecycleTest.Bridge bridge = new PreparationLifecycleTest.Bridge();
        try (PreparationLifecycleTest.Fixture f = new PreparationLifecycleTest.Fixture(bridge, new ProtocolClient(server), true)) {
            cached(f);
            f.runtime.select(PreparationLifecycleTest.ID, false);
            Runnable apply = bridge.callbacks.poll(10, TimeUnit.SECONDS);
            assertNotNull(apply); apply.run();
            assertEquals(1, server.sessions.get());
            assertEquals(PreparationLifecycleTest.UUID + ":" + Crypto.tokenHash(OLD), bridge.fingerprint);
            assertEquals(AccountPreparation.Phase.READY, f.runtime.preparation().snapshot().phase);
        }
    }

    @Test
    public void refusedOrUnverifiableServerResponsesDoNotInstallCachedCredentials() throws Exception {
        for (int mode = 0; mode < 5; mode++) {
            Server server = new Server(PreparationLifecycleTest.ID);
            server.sessionStatus = mode == 0 ? 429 : 200;
            server.missingCheck = mode == 1;
            server.bumpSettingsAfterDelivery = mode == 2;
            server.bumpOwnerAfterDelivery = mode == 3;
            server.bumpCredentialsAfterDelivery = mode == 4;
            PreparationLifecycleTest.Bridge bridge = new PreparationLifecycleTest.Bridge();
            try (PreparationLifecycleTest.Fixture f = new PreparationLifecycleTest.Fixture(bridge, new ProtocolClient(server), true)) {
                cached(f);
                f.runtime.select(PreparationLifecycleTest.ID, false);
                PreparationLifecycleTest.await(() -> f.runtime.preparation().snapshot().phase == AccountPreparation.Phase.FAILED);
                assertEquals(0, bridge.installed.get());
                assertNull(f.runtime.activeId());
            }
        }
    }

    @Test
    public void ordinaryOutageUsesOnlyTheExistingOfflineGrace() throws Exception {
        for (boolean expired : new boolean[] { false, true }) {
            Server server = new Server(PreparationLifecycleTest.ID);
            server.offline = true;
            PreparationLifecycleTest.Bridge bridge = new PreparationLifecycleTest.Bridge();
            try (PreparationLifecycleTest.Fixture f = new PreparationLifecycleTest.Fixture(bridge, new ProtocolClient(server), true)) {
                cached(f);
                if (expired) f.vault.update(data -> { data.getAsJsonObject("accounts").getAsJsonObject(PreparationLifecycleTest.ID)
                    .addProperty("offlineUntil", Instant.now().minusSeconds(1).toString()); return null; });
                f.runtime.select(PreparationLifecycleTest.ID, false);
                if (expired) {
                    PreparationLifecycleTest.await(() -> f.runtime.preparation().snapshot().phase == AccountPreparation.Phase.FAILED);
                    assertEquals(0, bridge.installed.get());
                } else {
                    Runnable apply = bridge.callbacks.poll(10, TimeUnit.SECONDS);
                    assertNotNull(apply); apply.run();
                    assertEquals(PreparationLifecycleTest.UUID + ":" + Crypto.tokenHash(OLD), bridge.fingerprint);
                }
                assertEquals(0, server.sessions.get());
            }
        }
    }
    @Test
    public void trustedServerRejectionClearsPersistentOfflineCredentials() throws Exception {
        Server server = new Server(PreparationLifecycleTest.ID);
        PreparationLifecycleTest.Bridge bridge = new PreparationLifecycleTest.Bridge();
        try (PreparationLifecycleTest.Fixture f = new PreparationLifecycleTest.Fixture(bridge, new ProtocolClient(server), true)) {
            cached(f); f.runtime.select(PreparationLifecycleTest.ID, false);
            Runnable apply = bridge.callbacks.poll(10, TimeUnit.SECONDS); assertNotNull(apply); apply.run();
            server.sessionRejected = true;
            java.lang.reflect.Field rev = MintAuthRuntime.class.getDeclaredField("selectionRevision"); rev.setAccessible(true);
            long revision = ((java.util.concurrent.atomic.AtomicLong) rev.get(f.runtime)).get();
            java.lang.reflect.Method prepare = MintAuthRuntime.class.getDeclaredMethod("prepare", String.class, boolean.class, boolean.class, long.class, boolean.class);
            prepare.setAccessible(true); prepare.invoke(f.runtime, PreparationLifecycleTest.ID, false, false, revision, false);
            assertNull(f.runtime.activeId());
            JsonObject stored = f.vault.read().getAsJsonObject("accounts").getAsJsonObject(PreparationLifecycleTest.ID);
            assertFalse(stored.has("ssid")); assertFalse(stored.has("offlineUntil"));
            assertFalse(stored.has("localRemoved"));
            Runnable restore = bridge.callbacks.poll(10, TimeUnit.SECONDS); assertNotNull(restore); restore.run();
            server.offline = true;
            f.runtime.select(PreparationLifecycleTest.ID, false);
            PreparationLifecycleTest.await(() -> f.runtime.preparation().snapshot().phase == AccountPreparation.Phase.FAILED);
            assertEquals(1, bridge.installed.get());
        }
    }

    @Test
    public void multiplayerDisableLeavesRemotePlayButKeepsSingleplayerAvailable() throws Exception {
        for (boolean remote : new boolean[] { false, true }) {
            Server server = new Server(PreparationLifecycleTest.ID);
            PreparationLifecycleTest.Bridge bridge = new PreparationLifecycleTest.Bridge() {
                public boolean multiplayerWorldOpen() { return remote; }
            };
            try (PreparationLifecycleTest.Fixture f = new PreparationLifecycleTest.Fixture(bridge, new ProtocolClient(server), true)) {
                cached(f); f.runtime.select(PreparationLifecycleTest.ID, false);
                Runnable apply = bridge.callbacks.poll(10, TimeUnit.SECONDS); assertNotNull(apply); apply.run();
                server.multiplayerDisabled = true;
                java.lang.reflect.Field rev = MintAuthRuntime.class.getDeclaredField("selectionRevision"); rev.setAccessible(true);
                long revision = ((java.util.concurrent.atomic.AtomicLong) rev.get(f.runtime)).get();
                java.lang.reflect.Method prepare = MintAuthRuntime.class.getDeclaredMethod("prepare", String.class, boolean.class, boolean.class, long.class, boolean.class);
                prepare.setAccessible(true); prepare.invoke(f.runtime, PreparationLifecycleTest.ID, false, false, revision, false);
                assertEquals(remote, f.runtime.activeId() == null);
            }
        }
    }

}
