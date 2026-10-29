// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import static org.junit.Assert.*;

import com.google.gson.*;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;

public class SecurityTest {
    @Test
    public void anotherInstanceCanHideOrReplaceAnAccountWithoutLatePreparationRestoringIt()
            throws Exception {
        Path root = Files.createTempDirectory("mintauth-late-preparation");
        MemoryStore store = new MemoryStore();
        try (Vault first = new Vault(root, store);
                Vault second = new Vault(root, store)) {
            first.unlock(null, false);
            seedLocal(first);
            second.unlock(null, false);
            first.update(
                    data -> {
                        data.getAsJsonObject("accounts")
                                .getAsJsonObject("local")
                                .addProperty("revision", 1);
                        return null;
                    });
            JsonObject prepared =
                    first.read().getAsJsonObject("accounts").getAsJsonObject("local").deepCopy();
            prepared.addProperty("ssid", "synthetic-late-token");
            second.update(
                    data -> {
                        JsonObject entry =
                                data.getAsJsonObject("accounts").getAsJsonObject("local");
                        entry.addProperty("hidden", true);
                        entry.remove("ssid");
                        return null;
                    });
            assertFalse(
                    first.update(
                            data ->
                                    AccountRecords.commitPrepared(
                                            data, "local", new JsonPrimitive(1), prepared)));
            assertFalse(
                    second.read().getAsJsonObject("accounts").getAsJsonObject("local").has("ssid"));
            second.update(
                    data -> {
                        JsonObject entry =
                                data.getAsJsonObject("accounts").getAsJsonObject("local");
                        entry.remove("hidden");
                        entry.addProperty("revision", 2);
                        entry.addProperty("ssid", "synthetic-newer-token");
                        return null;
                    });
            assertFalse(
                    first.update(
                            data ->
                                    AccountRecords.commitPrepared(
                                            data, "local", new JsonPrimitive(1), prepared)));
            assertEquals(
                    "synthetic-newer-token",
                    Json.string(
                            second.read().getAsJsonObject("accounts").getAsJsonObject("local"),
                            "ssid"));
        }
    }

    @Test
    public void jsonRejectsTrailingContentAndBoundsUtf8Bytes() {
        assertEquals("ok", Json.string(Json.object("{\"value\":\"ok\"}", 128), "value"));
        for (String invalid :
                Arrays.asList("{}{}", "{} trailing", "[1]", "{\"value\":\"éééééé\"}")) {
            try {
                Json.object(invalid, invalid.startsWith("{\"value") ? 15 : 128);
                fail();
            } catch (RuntimeException expected) {
            }
        }
    }

    @Test
    public void keyCleanupReferenceIsCommittedWithTheSecretAndCannotEscapeGeneration()
            throws Exception {
        Path root = Files.createTempDirectory("mintauth-key-reference");
        Vault vault = new Vault(root, new MemoryStore());
        vault.unlock(null, false);
        vault.update(
                data -> {
                    data.add("deviceKey", Json.obj("reference", "SOFTWARE"));
                    return null;
                });
        assertEquals("SOFTWARE", Json.string(vault.header(), "keyReference"));
        try {
            vault.update(
                    data -> {
                        data.add(
                                "deviceKey", Json.obj("reference", "CNG_TPM:" + UUID.randomUUID()));
                        return null;
                    });
            fail();
        } catch (java.io.IOException expected) {
        }
        assertEquals(
                "SOFTWARE", Json.string(vault.read().getAsJsonObject("deviceKey"), "reference"));
        vault.clearLocally();
        try {
            vault.update(
                    data -> {
                        data.add("deviceKey", Json.obj("reference", "SOFTWARE"));
                        return null;
                    });
            fail();
        } catch (Vault.Locked expected) {
        }
        vault.close();
    }

    @Test
    public void platformLabelsDoNotMistakeArm64ForX64() {
        assertEquals("WINDOWS_X64", RuntimePlatform.identifier("Windows 11", "amd64"));
        assertEquals("LINUX_X64", RuntimePlatform.identifier("Linux", "x86_64"));
        assertEquals("MACOS_ARM64", RuntimePlatform.identifier("Mac OS X", "aarch64"));
        assertEquals("MACOS_X64", RuntimePlatform.identifier("Mac OS X", "x86_64"));
        for (String os : Arrays.asList("Windows 11", "Linux"))
            for (String arch : Arrays.asList("arm64", "aarch64", "x86")) {
                try {
                    RuntimePlatform.identifier(os, arch);
                    fail();
                } catch (IllegalStateException expected) {
                }
            }
    }

    @Test
    public void offlineAllowanceRejectsRollbackAndNeverExceedsFifteenMinutes() {
        assertTrue(OfflineAllowance.persisted(100000, 99000, 100000, 200000));
        assertFalse(OfflineAllowance.persisted(90000, 99000, 100000, 200000));
        assertFalse(OfflineAllowance.persisted(200000, 99000, 100000, 200000));
        assertEquals(
                100 + java.util.concurrent.TimeUnit.MINUTES.toNanos(15),
                OfflineAllowance.deadline(100000, 100, 5000000));
    }

    private JsonObject enrollment(Vault vault) throws Exception {
        String generation = Json.string(vault.header(), "generation");
        vault.bind(UUID.randomUUID().toString(), generation);
        return vault.header();
    }

    private JsonObject command(JsonObject header) {
        JsonObject value = Json.obj("deviceId", Json.string(header, "deviceId"));
        value.addProperty("vaultGeneration", Json.string(header, "generation"));
        return value;
    }

    private void seedLocal(Vault vault) throws Exception {
        vault.update(
                data -> {
                    JsonObject local = Json.obj("source", "LOCAL");
                    local.addProperty("ssid", "synthetic-local-token");
                    JsonObject managed = Json.obj("source", "MANAGED");
                    managed.addProperty("ssid", "synthetic-managed-token");
                    JsonObject records = new JsonObject();
                    records.add("local", local);
                    records.add("managed", managed);
                    data.add("accounts", records);
                    return null;
                });
    }

    @Test
    public void relinkQuarantinesLocalsAndParentRevokeClearsPendingGeneration() throws Exception {
        Path root = Files.createTempDirectory("mintauth-relink-test");
        MemoryStore store = new MemoryStore();
        Vault vault = new Vault(root, store);
        vault.unlock(null, false);
        JsonObject old = enrollment(vault);
        seedLocal(vault);
        vault.beginRelink();
        assertNotEquals(Json.string(old, "generation"), Json.string(vault.header(), "generation"));
        JsonObject data = vault.read();
        assertFalse(data.has("accounts"));
        assertFalse(data.has("authorization"));
        assertEquals(1, data.getAsJsonObject("pendingLocalAccounts").size());
        vault.close();
        assertTrue(vault.clear(command(old)));
        assertTrue(vault.isWiped());
        try {
            vault.unlock(null, false);
            fail();
        } catch (Vault.Locked expected) {
            assertEquals("VAULT_REVOKED", expected.getMessage());
        }
    }

    @Test
    public void delayedParentCommandCannotEraseApprovedRelinkAndJournalRecoveryIsIdempotent()
            throws Exception {
        Path root = Files.createTempDirectory("mintauth-relink-approved");
        MemoryStore store = new MemoryStore();
        Vault vault = new Vault(root, store);
        vault.unlock(null, false);
        JsonObject old = enrollment(vault);
        seedLocal(vault);
        vault.beginRelink();
        JsonObject current = enrollment(vault);
        vault.update(
                data -> {
                    data.addProperty("approved", "retained");
                    return null;
                });
        Files.write(
                root.resolve("next-header.json"),
                Json.GSON.toJson(current).getBytes(StandardCharsets.UTF_8));
        vault.close();
        assertEquals(Json.string(current, "generation"), Json.string(vault.header(), "generation"));
        vault.unlock(null, false);
        assertTrue(vault.clear(command(old)));
        assertFalse(vault.isWiped());
        assertEquals("retained", Json.string(vault.read(), "approved"));
        vault.close();
    }

    @Test
    public void passwordRelinkKeepsWrappedMasterRecoverableAcrossRestart() throws Exception {
        Path root = Files.createTempDirectory("mintauth-password-relink");
        Vault vault = new Vault(root, null);
        char[] password = "synthetic wrapping password".toCharArray();
        vault.unlock(password, true);
        enrollment(vault);
        seedLocal(vault);
        vault.beginRelink();
        String generation = Json.string(vault.header(), "generation");
        vault.close();
        try {
            vault.unlock("wrong".toCharArray(), false);
            fail();
        } catch (Exception expected) {
        }
        assertEquals(generation, Json.string(vault.header(), "generation"));
        vault.unlock(password, false);
        assertTrue(vault.read().has("pendingLocalAccounts"));
        vault.close();
        Arrays.fill(password, '\0');
    }

    @Test
    public void failedMoveRetainsOriginalPlayLease() throws Exception {
        Path root = Files.createTempDirectory("mintauth-leases");
        String first = "00000000000000000000000000000001",
                second = "00000000000000000000000000000002";
        try (PlayLease a = new PlayLease(root);
                PlayLease b = new PlayLease(root);
                PlayLease observer = new PlayLease(root)) {
            assertTrue(a.acquire(first));
            assertTrue(b.acquire(second));
            assertFalse(a.acquire(second));
            assertFalse(observer.acquire(first));
            b.close();
            assertTrue(a.acquire(second));
            assertTrue(observer.acquire(first));
        }
    }

    static final class MemoryStore implements SecretStore {
        final Map<String, byte[]> values = new HashMap<>();

        public String name() {
            return "TEST";
        }

        public byte[] read(String generation) {
            return values.containsKey(generation) ? values.get(generation).clone() : null;
        }

        public void write(String generation, byte[] value) {
            values.put(generation, value.clone());
        }

        public void remove(String generation) {
            values.remove(generation);
        }
    }

    @Test
    public void cipherRejectsTamperAndWrongGeneration() throws Exception {
        byte[] key = Crypto.random(32),
                cipher =
                        Crypto.encrypt(
                                key,
                                "synthetic-token".getBytes(StandardCharsets.UTF_8),
                                "generation-a");
        assertEquals(
                "synthetic-token",
                new String(Crypto.decrypt(key, cipher, "generation-a"), StandardCharsets.UTF_8));
        try {
            Crypto.decrypt(key, cipher, "generation-b");
            fail();
        } catch (GeneralSecurityException expected) {
        }
        cipher[cipher.length - 1] ^= 1;
        try {
            Crypto.decrypt(key, cipher, "generation-a");
            fail();
        } catch (GeneralSecurityException expected) {
        }
    }

    @Test
    public void lockedRevocationStopsLateWritesAndCannotWipeRelink() throws Exception {
        Path root = Files.createTempDirectory("mintauth-vault-test");
        MemoryStore store = new MemoryStore();
        Vault vault = new Vault(root, store);
        vault.unlock(null, false);
        String generation = Json.string(vault.header(), "generation"),
                device = UUID.randomUUID().toString();
        vault.bind(device, generation);
        vault.update(
                data -> {
                    data.addProperty("ssid", "synthetic-secret");
                    return null;
                });
        vault.close();
        JsonObject wrong = new JsonObject();
        wrong.addProperty("vaultGeneration", UUID.randomUUID().toString());
        wrong.addProperty("deviceId", device);
        assertFalse(vault.clear(wrong));
        assertTrue(Files.exists(root.resolve("vault-" + generation + ".enc")));
        JsonObject command = wrong.deepCopy();
        command.addProperty("vaultGeneration", generation);
        assertTrue(vault.clear(command));
        assertFalse(Files.exists(root.resolve("vault-" + generation + ".enc")));
        try {
            vault.update(
                    data -> {
                        data.addProperty("ssid", "late");
                        return null;
                    });
            fail();
        } catch (Vault.Locked expected) {
            assertEquals("VAULT_REVOKED", expected.getMessage());
        }
        vault.resetAfterCleanup();
        vault.unlock(null, false);
        String next = Json.string(vault.header(), "generation");
        assertNotEquals(generation, next);
        vault.bind(UUID.randomUUID().toString(), next);
        assertFalse(vault.clear(command));
        assertFalse(vault.isWiped());
        vault.close();
    }

    @Test
    public void wrongPasswordDoesNotResetOrOverwriteData() throws Exception {
        Path root = Files.createTempDirectory("mintauth-password-test");
        Vault vault = new Vault(root, null);
        char[] pass = "synthetic test password".toCharArray();
        vault.unlock(pass, true);
        String generation = Json.string(vault.header(), "generation");
        vault.update(
                data -> {
                    data.addProperty("entry", "retained");
                    return null;
                });
        vault.close();
        try {
            vault.unlock("incorrect password".toCharArray(), true);
            fail();
        } catch (Vault.Locked expected) {
        }
        assertEquals(generation, Json.string(vault.header(), "generation"));
        vault.unlock(pass, true);
        assertEquals("retained", Json.string(vault.read(), "entry"));
        vault.close();
        Arrays.fill(pass, '\0');
    }

    @Test
    public void dpopSignatureBindsMethodUrlAndToken() throws Exception {
        KeyPair key = Crypto.ecKey();
        String proof =
                Crypto.proof(
                        Crypto.software(key.getPrivate(), Crypto.publicJwk(key.getPublic())),
                        "GET",
                        "https://automint.online/api/mintauth/v1/accounts",
                        "synthetic-token",
                        "synthetic-nonce");
        String[] p = proof.split("\\.");
        Signature verify = Signature.getInstance("SHA256withECDSA");
        verify.initVerify(key.getPublic());
        verify.update((p[0] + "." + p[1]).getBytes(StandardCharsets.US_ASCII));
        assertTrue(verify.verify(Crypto.derSignature(Crypto.unb64(p[2]))));
        JsonObject claims =
                Json.object(new String(Crypto.unb64(p[1]), StandardCharsets.UTF_8), 4096);
        assertEquals("GET", Json.string(claims, "htm"));
        assertEquals(Crypto.tokenHash("synthetic-token"), Json.string(claims, "ath"));
    }

    @Test
    public void forgedOrOldGenerationCleanupCannotBeAccepted() throws Exception {
        KeyPair key = Crypto.ecKey();
        Crypto.Signer signer = Crypto.software(key.getPrivate(), Crypto.publicJwk(key.getPublic()));
        JsonObject pub = signer.publicJwk();
        pub.addProperty("kid", "test-key");
        JsonArray keys = new JsonArray();
        keys.add(pub);
        String device = UUID.randomUUID().toString(), generation = UUID.randomUUID().toString();
        JsonObject h = Json.obj("alg", "ES256");
        h.addProperty("typ", "mintauth-cleanup+jwt");
        h.addProperty("kid", "test-key");
        JsonObject c = Json.obj("action", "CLEAR_MINTAUTH");
        c.addProperty("version", 1);
        c.addProperty("iss", "mintauth");
        c.addProperty("aud", "mintauth-cleanup-v1");
        c.addProperty("deviceId", device);
        c.addProperty("vaultGeneration", generation);
        c.addProperty("commandId", UUID.randomUUID().toString());
        String input =
                Crypto.b64(Json.GSON.toJson(h).getBytes(StandardCharsets.UTF_8))
                        + "."
                        + Crypto.b64(Json.GSON.toJson(c).getBytes(StandardCharsets.UTF_8));
        String jwt =
                input + "." + Crypto.b64(signer.sign(input.getBytes(StandardCharsets.US_ASCII)));
        assertEquals(
                generation,
                Json.string(
                        CleanupVerifier.verify(jwt, keys, device, generation), "vaultGeneration"));
        try {
            CleanupVerifier.verify(jwt, keys, device, UUID.randomUUID().toString());
            fail();
        } catch (GeneralSecurityException expected) {
        }
        byte[] sig = Crypto.unb64(jwt.substring(jwt.lastIndexOf('.') + 1));
        sig[0] ^= 1;
        try {
            CleanupVerifier.verify(input + "." + Crypto.b64(sig), keys, device, generation);
            fail();
        } catch (GeneralSecurityException expected) {
        }
    }
}
