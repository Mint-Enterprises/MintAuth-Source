// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import static org.junit.Assert.*;

import com.google.gson.*;

import org.junit.Test;

import java.util.*;
import java.util.concurrent.*;

public class AccountGroupsTest {
    static final String UUID = PreparationLifecycleTest.UUID;

    static JsonObject record(String id, String kind, String source) {
        JsonObject entry = Json.obj("id", id);
        entry.addProperty("uuid", UUID);
        entry.addProperty("ign", "SyntheticUser");
        entry.addProperty("kind", kind);
        entry.addProperty("source", source);
        entry.addProperty("status", "AVAILABLE");
        entry.addProperty("revision", 1);
        if ("LOCAL".equals(source))
            entry.addProperty("ssid", "synthetic-test-token-never-sent-to-network");
        return entry;
    }

    static MintAuthRuntime.AccountView view(JsonObject record) {
        return new MintAuthRuntime.AccountView(record);
    }

    @Test
    public void ownedCardWinsIndependentlyOfOrderingWithoutPromotingManualCredentials() {
        JsonObject local = record("local", "EXTERNAL", "LOCAL"),
                owned = record("owned", "OWNED", "MANAGED");
        for (List<MintAuthRuntime.AccountView> list :
                Arrays.asList(
                        Arrays.asList(view(local), view(owned)),
                        Arrays.asList(view(owned), view(local)))) {
            List<MintAuthRuntime.AccountView> cards = AccountGroups.cards(list);
            assertEquals(1, cards.size());
            assertEquals("owned", cards.get(0).id);
            assertEquals(2, AccountGroups.sources(list, UUID).size());
            assertFalse(cards.get(0).savedOnDevice);
        }
        assertEquals("LOCAL", Json.string(local, "source"));
        assertTrue(local.has("ssid"));
        owned.addProperty("status", "UNAVAILABLE");
        assertEquals(
                "owned", AccountGroups.cards(Arrays.asList(view(local), view(owned))).get(0).id);
    }

    @Test
    public void groupsValidatedUuidNotNamesOrAuthorityContexts() {
        JsonObject first = record("one", "EXTERNAL", "LOCAL"),
                second = record("two", "OWNED", "MANAGED");
        second.addProperty("ign", "RenamedUser");
        second.addProperty("uuid", "11111111-1111-1111-1111-111111111111");
        assertEquals(1, AccountGroups.cards(Arrays.asList(view(first), view(second))).size());
        second.addProperty("uuid", "22222222222222222222222222222222");
        second.addProperty("ign", "SyntheticUser");
        assertEquals(2, AccountGroups.cards(Arrays.asList(view(first), view(second))).size());
        first.addProperty("uuid", "bad");
        second.addProperty("uuid", "bad");
        assertEquals(2, AccountGroups.cards(Arrays.asList(view(first), view(second))).size());
    }

    @Test
    public void addingMintCatalogEntryPreservesInstalledManualSessionAndUnlocksAfterLauncher()
            throws Exception {
        PreparationLifecycleTest.Bridge bridge = new PreparationLifecycleTest.Bridge();
        try (PreparationLifecycleTest.Fixture f =
                new PreparationLifecycleTest.Fixture(
                        bridge, PreparationLifecycleTest.localProfile(), false)) {
            f.runtime.select(PreparationLifecycleTest.ID, false);
            Runnable install = bridge.callbacks.poll(5, TimeUnit.SECONDS);
            assertNotNull(install);
            install.run();
            String original = bridge.fingerprint;
            f.vault.update(
                    data -> {
                        data.getAsJsonObject("accounts")
                                .add("owned", record("owned", "OWNED", "MANAGED"));
                        return null;
                    });
            f.runtime.open();
            PreparationLifecycleTest.await(() -> f.runtime.accounts().size() == 2);
            MintAuthRuntime.AccountView card = f.runtime.accountCards().get(0);
            assertEquals("owned", card.id);
            assertEquals(1, f.runtime.accountCards().size());
            assertEquals(PreparationLifecycleTest.ID, f.runtime.playingAccountId());
            assertTrue(f.runtime.isPlaying(card));
            assertTrue(f.runtime.canUseMintSession(card));
            assertEquals("pasted SSID", f.runtime.playingSourceLabel());
            assertEquals(original, bridge.fingerprint);
            assertEquals(1, bridge.installed.get());
            f.runtime.restoreLauncher();
            Runnable restore = bridge.callbacks.poll(5, TimeUnit.SECONDS);
            assertNotNull(restore);
            restore.run();
            assertFalse(f.runtime.isPlaying(card));
            assertFalse(f.runtime.canUseMintSession(card));
            assertEquals("owned", f.runtime.accountCards().get(0).id);
        }
    }

    @Test
    public void removalAfterPreparationCommitStillFencesClientCallback() throws Exception {
        PreparationLifecycleTest.Bridge bridge = new PreparationLifecycleTest.Bridge();
        try (PreparationLifecycleTest.Fixture f =
                new PreparationLifecycleTest.Fixture(
                        bridge, PreparationLifecycleTest.localProfile(), false)) {
            f.runtime.select(PreparationLifecycleTest.ID, false);
            Runnable install = bridge.callbacks.poll(5, TimeUnit.SECONDS);
            assertNotNull(install);
            f.vault.update(
                    data -> {
                        AccountRecords.removeLocalCopy(
                                data.getAsJsonObject("accounts")
                                        .getAsJsonObject(PreparationLifecycleTest.ID),
                                false);
                        return null;
                    });
            install.run();
            assertEquals(0, bridge.installed.get());
            assertNull(f.runtime.activeId());
            assertEquals(AccountPreparation.Phase.FAILED, f.runtime.preparation().snapshot().phase);
        }
    }

    @Test
    public void replacementAfterPreparationCommitStillFencesClientCallback() throws Exception {
        PreparationLifecycleTest.Bridge bridge = new PreparationLifecycleTest.Bridge();
        try (PreparationLifecycleTest.Fixture f =
                new PreparationLifecycleTest.Fixture(
                        bridge, PreparationLifecycleTest.localProfile(), false)) {
            f.runtime.select(PreparationLifecycleTest.ID, false);
            Runnable install = bridge.callbacks.poll(5, TimeUnit.SECONDS);
            assertNotNull(install);
            f.vault.update(
                    data -> {
                        JsonObject entry =
                                data.getAsJsonObject("accounts")
                                        .getAsJsonObject(PreparationLifecycleTest.ID);
                        entry.addProperty("ssid", "synthetic-replacement-token");
                        entry.addProperty("revision", 2);
                        return null;
                    });
            install.run();
            assertEquals(0, bridge.installed.get());
            assertNull(f.runtime.activeId());
        }
    }

    @Test
    public void cloudSyncKeepsLocalIdentityAndNeverRestoresDeletedOrReplacedCopies() {
        JsonObject local = record("local", "EXTERNAL", "LOCAL"),
                remote = record("cloud", "EXTERNAL", "CLOUD");
        remote.remove("source");
        remote.remove("ssid");
        remote.addProperty("status", "PENDING");
        JsonObject data = new JsonObject(), entries = new JsonObject();
        data.add("accounts", entries);
        entries.add("local", local);
        JsonObject expected = local.deepCopy();
        assertTrue(AccountRecords.needsSync(local));
        assertTrue(AccountRecords.saveCloudCopy(data, "local", expected, remote, "grant"));
        assertTrue(entries.getAsJsonObject("local").has("ssid"));
        assertEquals("LOCAL", Json.string(local, "source"));
        assertFalse(AccountRecords.needsSync(local));
        assertFalse(entries.getAsJsonObject("cloud").has("ssid"));
        JsonObject cloud = entries.getAsJsonObject("cloud");
        cloud.addProperty("status", "DELETED");
        assertFalse(AccountRecords.saveCloudCopy(data, "local", expected, remote, "grant"));
        AccountRecords.applyCloudTombstones(data);
        assertTrue(local.has("hidden"));
        assertFalse(local.has("ssid"));
        JsonObject changed = record("replacement", "EXTERNAL", "LOCAL");
        entries.add("replacement", changed);
        JsonObject before = changed.deepCopy();
        changed.addProperty("revision", 2);
        assertFalse(AccountRecords.saveCloudCopy(data, "replacement", before, remote, "grant"));
    }

    @Test
    public void cloudCopyArrivingBeforeApplyDoesNotStrandTheActiveLocalRecord() throws Exception {
        PreparationLifecycleTest.Bridge bridge = new PreparationLifecycleTest.Bridge();
        try (PreparationLifecycleTest.Fixture f =
                new PreparationLifecycleTest.Fixture(
                        bridge, PreparationLifecycleTest.localProfile(), false)) {
            f.runtime.select(PreparationLifecycleTest.ID, false);
            Runnable install = bridge.callbacks.poll(5, TimeUnit.SECONDS);
            assertNotNull(install);
            f.vault.update(
                    data -> {
                        JsonObject local =
                                data.getAsJsonObject("accounts")
                                        .getAsJsonObject(PreparationLifecycleTest.ID);
                        JsonObject cloud = record("cloud-copy", "EXTERNAL", "CLOUD");
                        cloud.remove("ssid");
                        assertTrue(
                                AccountRecords.saveCloudCopy(
                                        data,
                                        PreparationLifecycleTest.ID,
                                        local.deepCopy(),
                                        cloud,
                                        "grant"));
                        return null;
                    });
            install.run();
            assertEquals(1, bridge.installed.get());
            assertEquals(PreparationLifecycleTest.ID, f.runtime.activeId());
            assertTrue(f.runtime.checkBeforeAuthentication(bridge.fingerprint));
            JsonObject data = f.vault.read();
            assertTrue(data.getAsJsonObject("accounts").has("cloud-copy"));
            assertEquals(
                    "LOCAL",
                    Json.string(
                            data.getAsJsonObject("accounts")
                                    .getAsJsonObject(PreparationLifecycleTest.ID),
                            "source"));
        }
    }

    @Test
    public void preparationPreservesAConcurrentSyncMarkerWithoutChangingProvenance() {
        JsonObject original = record("local", "EXTERNAL", "LOCAL"),
                data = new JsonObject(),
                entries = new JsonObject();
        data.add("accounts", entries);
        entries.add("local", original);
        JsonObject prepared = original.deepCopy();
        original.addProperty("cloudCopyId", "cloud");
        original.addProperty("syncedLocalRevision", 1);
        assertTrue(
                AccountRecords.commitPrepared(data, "local", new JsonPrimitive(1), prepared, true));
        JsonObject current = entries.getAsJsonObject("local");
        assertEquals("cloud", Json.string(current, "cloudCopyId"));
        assertFalse(AccountRecords.needsSync(current));
        assertEquals("LOCAL", Json.string(current, "source"));
    }

    @Test
    public void explicitMintSwitchRechecksItsOwnAuthorityAndDoesNotBorrowManualToken()
            throws Exception {
        FreshMintLoginTest.Server server = new FreshMintLoginTest.Server("owned");
        ProtocolClient api = new ProtocolClient(server);
        PreparationLifecycleTest.Bridge bridge = new PreparationLifecycleTest.Bridge();
        try (PreparationLifecycleTest.Fixture f =
                new PreparationLifecycleTest.Fixture(bridge, api, false)) {
            f.runtime.select(PreparationLifecycleTest.ID, false);
            Runnable first = bridge.callbacks.poll(5, TimeUnit.SECONDS);
            assertNotNull(first);
            first.run();
            String pasted = bridge.fingerprint;
            f.vault.update(
                    data -> {
                        JsonObject owned = record("owned", "OWNED", "MANAGED");
                        owned.addProperty("ssid", "synthetic-managed-token-distinct-from-local");
                        owned.addProperty("tokenCheckedAt", java.time.Instant.now().toString());
                        owned.addProperty("authorityStamp", "version/1/\"generation\"/1");
                        JsonObject context = Json.obj("kind", "INVENTORY");
                        context.addProperty("accountId", "owned");
                        owned.add("context", context);
                        data.getAsJsonObject("accounts").add("owned", owned);
                        JsonObject auth = Json.obj("access_token", "synthetic-authorization");
                        auth.addProperty("device_id", "synthetic-device");
                        auth.addProperty("subject", "synthetic-user");
                        auth.addProperty("vault_generation", "synthetic-generation");
                        data.add("authorization", auth);
                        return null;
                    });
            f.runtime.open();
            PreparationLifecycleTest.await(() -> f.runtime.accounts().size() == 2);
            assertEquals(pasted, bridge.fingerprint);
            assertEquals(0, server.authorizations.get());
            f.runtime.select(f.runtime.accountCards().get(0).id, false);
            Runnable apply = bridge.callbacks.poll(5, TimeUnit.SECONDS);
            assertNotNull(apply);
            assertEquals(2, server.authorizations.get());
            assertEquals(pasted, bridge.fingerprint);
            apply.run();
            assertEquals("owned", f.runtime.playingAccountId());
            assertNotEquals(pasted, bridge.fingerprint);
            assertEquals("Mint session", f.runtime.playingSourceLabel());
            assertTrue(
                    f.vault
                            .read()
                            .getAsJsonObject("accounts")
                            .getAsJsonObject(PreparationLifecycleTest.ID)
                            .has("ssid"));
        }
    }

    @Test
    public void deletingCloudCopyImmediatelyClearsItsSyncedActiveLocalCopy() throws Exception {
        ProtocolClient api =
                new ProtocolClient(
                        (url, method) -> {
                            if (url.endsWith("/external/delete"))
                                return PreparationLifecycleTest.response(url, "{}");
                            if (url.endsWith("/player/attributes"))
                                return PreparationLifecycleTest.response(
                                        url,
                                        "{\"privileges\":{\"multiplayerServer\":{\"enabled\":true}}}");
                            assertEquals(
                                    "https://api.minecraftservices.com/minecraft/profile", url);
                            return PreparationLifecycleTest.response(
                                    url, "{\"id\":\"" + UUID + "\",\"name\":\"SyntheticUser\"}");
                        });
        PreparationLifecycleTest.Bridge bridge = new PreparationLifecycleTest.Bridge();
        try (PreparationLifecycleTest.Fixture f =
                new PreparationLifecycleTest.Fixture(bridge, api, false)) {
            f.runtime.select(PreparationLifecycleTest.ID, false);
            Runnable first = bridge.callbacks.poll(5, TimeUnit.SECONDS);
            assertNotNull(first);
            first.run();
            f.vault.update(
                    data -> {
                        JsonObject local =
                                data.getAsJsonObject("accounts")
                                        .getAsJsonObject(PreparationLifecycleTest.ID);
                        JsonObject cloud = record("cloud", "EXTERNAL", "CLOUD");
                        assertTrue(
                                AccountRecords.saveCloudCopy(
                                        data,
                                        PreparationLifecycleTest.ID,
                                        local.deepCopy(),
                                        cloud,
                                        "grant"));
                        JsonObject auth = Json.obj("access_token", "synthetic-authorization");
                        auth.addProperty("device_id", "grant");
                        data.add("authorization", auth);
                        return null;
                    });
            f.runtime.remove("cloud", true);
            long operation = f.runtime.submittedOperation();
            PreparationLifecycleTest.await(() -> f.runtime.completedOperation(operation) != null);
            JsonObject local =
                    f.vault
                            .read()
                            .getAsJsonObject("accounts")
                            .getAsJsonObject(PreparationLifecycleTest.ID);
            assertTrue(local.has("hidden"));
            assertFalse(local.has("ssid"));
            assertNull(f.runtime.activeId());
            Runnable clear = bridge.callbacks.poll(5, TimeUnit.SECONDS);
            assertNotNull(clear);
            clear.run();
            assertNull(bridge.fingerprint);
        }
    }
}
