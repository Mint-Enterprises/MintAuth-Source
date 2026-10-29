// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import static org.junit.Assert.*;

import com.google.gson.JsonObject;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class StartupIdentityTest {
    private static void legacySelection(PreparationLifecycleTest.Fixture fixture) throws Exception {
        Files.write(
                fixture.root.resolve("preferences.json"),
                ("{\"lastSelection\":\"" + PreparationLifecycleTest.ID + "\"}")
                        .getBytes(StandardCharsets.UTF_8));
        KeyPair pair = Crypto.ecKey();
        JsonObject key = Json.obj("reference", "SOFTWARE");
        key.addProperty("privateKey", Crypto.b64(pair.getPrivate().getEncoded()));
        key.add("publicKey", Crypto.publicJwk(pair.getPublic()));
        fixture.vault.update(
                data -> {
                    data.add("deviceKey", key);
                    return null;
                });
    }

    private static ProtocolClient profile(AtomicInteger requests) {
        return new ProtocolClient(
                (url, method) -> {
                    requests.incrementAndGet();
                    if (url.equals("https://api.minecraftservices.com/player/attributes"))
                        return PreparationLifecycleTest.response(
                                url,
                                "{\"privileges\":{\"multiplayerServer\":{\"enabled\":true}},\"bannedScopes\":{}}");
                    assertEquals("https://api.minecraftservices.com/minecraft/profile", url);
                    return PreparationLifecycleTest.response(
                            url,
                            "{\"id\":\""
                                    + PreparationLifecycleTest.UUID
                                    + "\",\"name\":\"SyntheticUser\"}");
                });
    }

    @Test
    public void startupIgnoresLegacyLastSelectionAndKeepsSavedAccountsUsable() throws Exception {
        PreparationLifecycleTest.Bridge bridge = new PreparationLifecycleTest.Bridge();
        bridge.fingerprint = "synthetic-launcher-identity";
        AtomicInteger requests = new AtomicInteger();
        try (PreparationLifecycleTest.Fixture fixture =
                new PreparationLifecycleTest.Fixture(bridge, profile(requests), false)) {
            legacySelection(fixture);
            fixture.runtime.loadSavedAccounts();
            assertEquals(1, fixture.runtime.accounts().size());
            assertEquals(PreparationLifecycleTest.ID, fixture.runtime.accounts().get(0).id);
            assertNull(fixture.runtime.activeId());
            assertNull(fixture.runtime.preparation());
            assertEquals("synthetic-launcher-identity", bridge.fingerprint);
            assertEquals(0, bridge.installed.get());
            assertEquals(0, requests.get());
            assertTrue(bridge.callbacks.isEmpty());

            fixture.runtime.select(PreparationLifecycleTest.ID, false);
            Runnable install = bridge.callbacks.poll(5, TimeUnit.SECONDS);
            assertNotNull(install);
            install.run();
            assertEquals(PreparationLifecycleTest.ID, fixture.runtime.playingAccountId());
            assertEquals(1, bridge.installed.get());
            assertEquals(2, requests.get());
        }
    }

    @Test
    public void unlockingDoesNotRestoreLegacySelectionEither() throws Exception {
        PreparationLifecycleTest.Bridge bridge = new PreparationLifecycleTest.Bridge();
        bridge.fingerprint = "synthetic-launcher-identity";
        AtomicInteger requests = new AtomicInteger();
        try (PreparationLifecycleTest.Fixture fixture =
                new PreparationLifecycleTest.Fixture(bridge, profile(requests), false)) {
            legacySelection(fixture);
            fixture.runtime.unlock(new char[0], false);
            long ticket = fixture.runtime.submittedOperation();
            PreparationLifecycleTest.await(
                    () -> fixture.runtime.completedOperation(ticket) != null);
            assertTrue(fixture.runtime.completedOperation(ticket).succeeded);
            assertEquals(1, fixture.runtime.accounts().size());
            assertNull(fixture.runtime.activeId());
            assertNull(fixture.runtime.preparation());
            assertEquals("synthetic-launcher-identity", bridge.fingerprint);
            assertEquals(0, bridge.installed.get());
            assertEquals(0, requests.get());
            assertTrue(bridge.callbacks.isEmpty());
        }
    }
}
