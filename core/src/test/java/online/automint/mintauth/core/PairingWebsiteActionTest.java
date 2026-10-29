// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import static org.junit.Assert.*;

import org.junit.Test;

import java.awt.HeadlessException;
import java.net.URI;
import java.util.ArrayDeque;
import java.util.Queue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

public class PairingWebsiteActionTest {
    private static void softwareKey(PreparationLifecycleTest.Fixture fixture) throws Exception {
        java.security.KeyPair pair = Crypto.ecKey();
        com.google.gson.JsonObject key = Json.obj("reference", "SOFTWARE");
        key.addProperty("privateKey", Crypto.b64(pair.getPrivate().getEncoded()));
        key.add("publicKey", Crypto.publicJwk(pair.getPublic()));
        fixture.vault.update(
                data -> {
                    data.add("deviceKey", key);
                    return null;
                });
    }

    @Test
    public void dispatchIsIndependentDeduplicatedAndUsesOnlyTheFixedMintLink() {
        Queue<Runnable> pending = new ArrayDeque<>();
        AtomicReference<URI> opened = new AtomicReference<>();
        PairingWebsiteAction action = new PairingWebsiteAction(pending::add, opened::set);
        action.begin("ABCD-EFGH");
        action.open();
        action.open();
        assertEquals(1, pending.size());
        assertTrue(action.opening());
        assertNull(opened.get());
        pending.remove().run();
        assertEquals(
                "https://automint.online/mintauth/link#code=ABCDEFGH", opened.get().toString());
        assertFalse(action.opening());
        assertTrue(action.notice().contains("Approve"));
    }

    @Test
    public void failureIsVisibleAndRetryCanSucceedWithoutLeakingErrors() {
        AtomicInteger calls = new AtomicInteger();
        PairingWebsiteAction action =
                new PairingWebsiteAction(
                        Runnable::run,
                        uri -> {
                            if (calls.incrementAndGet() == 1)
                                throw new HeadlessException("SECRET_SENTINEL");
                        });
        action.begin("ABCD-EFGH");
        action.open();
        assertFalse(action.opening());
        assertTrue(action.notice().contains("Copy link"));
        assertFalse(action.notice().contains("SECRET_SENTINEL"));
        action.copied(true);
        assertTrue(action.notice().contains("copied"));
        action.open();
        assertEquals(2, calls.get());
        assertTrue(action.notice().contains("Approve"));
    }

    @Test
    public void changedPairingAndCleanupFenceQueuedAndLateResults() {
        Queue<Runnable> pending = new ArrayDeque<>();
        AtomicReference<URI> opened = new AtomicReference<>();
        PairingWebsiteAction action = new PairingWebsiteAction(pending::add, opened::set);
        action.begin("ABCD-EFGH");
        action.open();
        action.clear();
        pending.remove().run();
        assertNull(opened.get());
        assertNull(action.notice());
        PairingWebsiteAction[] holder = new PairingWebsiteAction[1];
        holder[0] =
                new PairingWebsiteAction(
                        Runnable::run,
                        uri -> {
                            holder[0].begin("JKLM-NPQR");
                            throw new Exception("OLD_SECRET");
                        });
        holder[0].begin("ABCD-EFGH");
        holder[0].open();
        assertNull(holder[0].notice());
        assertTrue(holder[0].link().endsWith("#code=JKLMNPQR"));
    }

    @Test
    public void malformedCodesAndNonMintUrisCannotReachTheNativeOpener() throws Exception {
        for (String code :
                new String[] {"ABCD-EFGH/evil", "https://evil.test", "ABCD-EFGI", "ABCDEFGH"}) {
            try {
                PairingWebsiteAction.uri(code);
                fail();
            } catch (IllegalArgumentException expected) {
            }
        }
        for (String uri :
                new String[] {
                    "file:///tmp/test",
                    "https://automint.online.evil.test/mintauth/link",
                    "https://automint.online/mintauth/link#code=ABCD&evil=1",
                    "https://evil.test"
                }) {
            try {
                NativeStores.openWebsite(uri);
                fail();
            } catch (java.io.IOException expected) {
                assertEquals("WEBSITE_URL_INVALID", expected.getMessage());
            }
        }
    }

    @Test
    public void runtimeUsesGameNativeOpenerAndRestoresExistingLinkedState() throws Exception {
        AtomicReference<URI> opened = new AtomicReference<>();
        PreparationLifecycleTest.Bridge bridge =
                new PreparationLifecycleTest.Bridge() {
                    @Override
                    public void openWebsite(URI uri) {
                        opened.set(uri);
                    }
                };
        ProtocolClient protocol =
                new ProtocolClient(
                        (url, method) -> {
                            assertTrue(url.endsWith("/device/code"));
                            return PreparationLifecycleTest.response(
                                    url,
                                    "{\"user_code\":\"ABCD-EFGH\",\"device_code\":\"synthetic-device-code\",\"verification_uri_complete\":\"https://automint.online/mintauth/link#code=ABCDEFGH\"}");
                        });
        try (PreparationLifecycleTest.Fixture fixture =
                new PreparationLifecycleTest.Fixture(bridge, protocol, false)) {
            softwareKey(fixture);
            fixture.runtime.loadSavedAccounts();
            fixture.runtime.beginLink();
            long ticket = fixture.runtime.submittedOperation();
            PreparationLifecycleTest.await(
                    () -> fixture.runtime.completedOperation(ticket) != null);
            assertTrue(fixture.runtime.completedOperation(ticket).succeeded);
            fixture.runtime.openPairingWebsite();
            PreparationLifecycleTest.await(() -> opened.get() != null);
            assertTrue(opened.get().toString().endsWith("#code=ABCDEFGH"));
        }
        try (PreparationLifecycleTest.Fixture fixture =
                new PreparationLifecycleTest.Fixture(bridge, protocol, true)) {
            softwareKey(fixture);
            fixture.runtime.loadSavedAccounts();
            java.lang.reflect.Field linked = MintAuthRuntime.class.getDeclaredField("linked");
            linked.setAccessible(true);
            linked.set(fixture.runtime, false);
            fixture.runtime.beginLink();
            long ticket = fixture.runtime.submittedOperation();
            PreparationLifecycleTest.await(
                    () -> fixture.runtime.completedOperation(ticket) != null);
            assertTrue(fixture.runtime.linked());
            assertTrue(fixture.runtime.pairingCode().isEmpty());
            assertTrue(fixture.vault.read().has("authorization"));
        }
    }
}
