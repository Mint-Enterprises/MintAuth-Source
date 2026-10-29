// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import static org.junit.Assert.*;

import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public class CloudRemovalTest {
    private static JsonObject account(String source) {
        JsonObject value = Json.obj("id", "synthetic-account");
        value.addProperty("source", source);
        value.addProperty("kind", "MANAGED".equals(source) ? "OWNED" : "EXTERNAL");
        value.addProperty("uuid", "11111111111111111111111111111111");
        value.addProperty("ign", "SyntheticUser");
        value.addProperty("revision", 1);
        value.addProperty("status", "AVAILABLE");
        value.addProperty("grantId", "synthetic-grant");
        return value;
    }

    private static JsonObject data(JsonObject record) {
        JsonObject data = new JsonObject(), accounts = new JsonObject();
        accounts.add("synthetic-account", record);
        data.add("accounts", accounts);
        return data;
    }

    @Test
    public void removingRemoteCopiesLeavesTheirCatalogEntriesVisible() {
        for (String source : Arrays.asList("MANAGED", "CLOUD")) {
            JsonObject record = account(source);
            record.addProperty("ssid", "synthetic-cached-token");
            record.addProperty("offlineUntil", "2026-10-28T14:00:00Z");
            record.addProperty("authorityStamp", "synthetic-authority");
            AccountRecords.removeLocalCopy(record, false);
            assertFalse(record.has("hidden"));
            assertFalse(record.has("ssid"));
            assertFalse(record.has("offlineUntil"));
            assertFalse(record.has("authorityStamp"));
            assertEquals("AVAILABLE", Json.string(record, "status"));
            assertFalse(AccountRecords.canRestore(record));
            MintAuthRuntime.AccountView view = new MintAuthRuntime.AccountView(record);
            assertTrue(view.onAutoMint);
            assertFalse(view.savedOnDevice);
            assertEquals("SyntheticUser", view.ign);
        }
    }

    @Test
    public void refreshRepairsOldHiddenCloudEntriesWithoutRestoringSecrets() {
        JsonObject old = account("MANAGED");
        old.addProperty("hidden", true);
        old.addProperty("ssid", "synthetic-old-token");
        JsonObject merged = AccountRecords.mergeRemote(old, account("MANAGED"), "synthetic-grant");
        assertFalse(merged.has("hidden"));
        assertFalse(merged.has("ssid"));
        assertTrue(AccountRecords.locallyRemoved(merged));
        assertFalse(AccountRecords.canRestore(merged));
        String fence = Json.string(merged, "deviceRevision");
        merged = AccountRecords.mergeRemote(merged, account("MANAGED"), "synthetic-grant");
        assertEquals(fence, Json.string(merged, "deviceRevision"));
        assertFalse(merged.has("ssid"));
        assertTrue(AccountRecords.locallyRemoved(merged));
    }

    @Test
    public void localOnlyRemovalAndDeleteEverywhereRemainHidden() {
        JsonObject local = account("LOCAL");
        local.addProperty("ssid", "synthetic-local-token");
        AccountRecords.removeLocalCopy(local, false);
        assertTrue(local.has("hidden"));
        assertEquals("UNAVAILABLE", Json.string(local, "status"));
        assertFalse(local.has("ssid"));
        JsonObject deleted = account("CLOUD");
        AccountRecords.removeLocalCopy(deleted, true);
        assertEquals("DELETED", Json.string(deleted, "status"));
        JsonObject stale = AccountRecords.mergeRemote(deleted, account("CLOUD"), "synthetic-grant");
        assertEquals("DELETED", Json.string(stale, "status"));
        assertTrue(stale.has("hidden"));
        AccountRecords.removeLocalCopy(stale, false);
        assertEquals("DELETED", Json.string(stale, "status"));
    }

    @Test
    public void onlyAnExplicitSelectionCanSaveARemovedCopyAgain() {
        JsonObject record = account("MANAGED");
        AccountRecords.removeLocalCopy(record, false);
        JsonObject store = data(record), prepared = record.deepCopy();
        prepared.addProperty("ssid", "synthetic-new-token");
        assertFalse(
                AccountRecords.commitPrepared(
                        store, "synthetic-account", new JsonPrimitive(1), prepared));
        assertTrue(
                AccountRecords.commitPrepared(
                        store, "synthetic-account", new JsonPrimitive(1), prepared, true));
        JsonObject saved = store.getAsJsonObject("accounts").getAsJsonObject("synthetic-account");
        assertFalse(AccountRecords.locallyRemoved(saved));
        assertTrue(AccountRecords.canRestore(saved));
        assertEquals("synthetic-new-token", Json.string(saved, "ssid"));
    }

    @Test
    public void aSecondRemovalFencesAnAlreadyExplicitPreparation() {
        JsonObject record = account("MANAGED");
        AccountRecords.removeLocalCopy(record, false);
        JsonObject prepared = record.deepCopy();
        prepared.addProperty("ssid", "synthetic-late-token");
        String before = Json.string(record, "deviceRevision");
        AccountRecords.removeLocalCopy(record, false);
        assertNotEquals(before, Json.string(record, "deviceRevision"));
        assertFalse(
                AccountRecords.commitPrepared(
                        data(record), "synthetic-account", new JsonPrimitive(1), prepared, true));
        assertFalse(record.has("ssid"));
    }

    @Test
    public void cacheCannotCrossGrantUuidOrRevisionChanges() {
        JsonObject record = account("MANAGED");
        record.addProperty("ssid", "synthetic-existing-token");
        assertTrue(
                AccountRecords.mergeRemote(record, account("MANAGED"), "synthetic-grant")
                        .has("ssid"));
        assertFalse(
                AccountRecords.mergeRemote(record, account("MANAGED"), "different-grant")
                        .has("ssid"));
        JsonObject changed = account("MANAGED");
        changed.addProperty("revision", 2);
        assertFalse(AccountRecords.mergeRemote(record, changed, "synthetic-grant").has("ssid"));
        changed = account("MANAGED");
        changed.addProperty("uuid", "22222222222222222222222222222222");
        assertFalse(AccountRecords.mergeRemote(record, changed, "synthetic-grant").has("ssid"));
    }

    @Test
    public void anotherVaultInstanceCannotRepopulateARemovedCloudCopy() throws Exception {
        Path root = Files.createTempDirectory("mintauth-cloud-removal-");
        SecurityTest.MemoryStore keys = new SecurityTest.MemoryStore();
        try (Vault first = new Vault(root, keys);
                Vault second = new Vault(root, keys)) {
            first.unlock(null, false);
            first.update(
                    value -> {
                        value.add("accounts", data(account("MANAGED")).get("accounts"));
                        return null;
                    });
            second.unlock(null, false);
            JsonObject prepared =
                    first.read()
                            .getAsJsonObject("accounts")
                            .getAsJsonObject("synthetic-account")
                            .deepCopy();
            prepared.addProperty("ssid", "synthetic-inflight-token");
            second.update(
                    value -> {
                        AccountRecords.removeLocalCopy(
                                value.getAsJsonObject("accounts")
                                        .getAsJsonObject("synthetic-account"),
                                false);
                        return null;
                    });
            assertFalse(
                    first.update(
                            value ->
                                    AccountRecords.commitPrepared(
                                            value,
                                            "synthetic-account",
                                            new JsonPrimitive(1),
                                            prepared,
                                            true)));
            JsonObject after =
                    second.read().getAsJsonObject("accounts").getAsJsonObject("synthetic-account");
            assertFalse(after.has("hidden"));
            assertFalse(after.has("ssid"));
            assertTrue(AccountRecords.locallyRemoved(after));
        } finally {
            if (!root.toAbsolutePath()
                            .normalize()
                            .getParent()
                            .equals(
                                    java.nio.file.Paths.get(System.getProperty("java.io.tmpdir"))
                                            .toAbsolutePath()
                                            .normalize())
                    || !root.getFileName().toString().startsWith("mintauth-cloud-removal-"))
                throw new java.io.IOException("Unsafe test cleanup");
            try (java.util.stream.Stream<Path> paths = Files.walk(root)) {
                for (Path path :
                        (Iterable<Path>)
                                paths.sorted(java.util.Comparator.reverseOrder())::iterator)
                    Files.delete(path);
            }
        }
    }
}
