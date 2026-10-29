// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import static org.junit.Assert.*;

import com.google.gson.JsonObject;

import org.junit.Test;

import java.io.IOException;
import java.nio.file.*;
import java.security.KeyPair;
import java.util.concurrent.atomic.AtomicBoolean;

public class NativeStorageRecoveryTest {
    @Test
    public void retryReopensOriginalOsVaultWithoutLosingAccountsOrCreatingPasswordStore()
            throws Exception {
        Path root = Files.createTempDirectory("mintauth-native-retry");
        SecurityTest.MemoryStore backing = new SecurityTest.MemoryStore();
        AtomicBoolean unavailable = new AtomicBoolean(false);
        SecretStore store =
                new SecretStore() {
                    public String name() {
                        return backing.name();
                    }

                    public byte[] read(String generation) throws Exception {
                        if (unavailable.get()) throw new IOException("synthetic locked keychain");
                        return backing.read(generation);
                    }

                    public void write(String generation, byte[] key) throws Exception {
                        backing.write(generation, key);
                    }

                    public void remove(String generation) throws Exception {
                        backing.remove(generation);
                    }
                };
        String generation;
        try (Vault seed = new Vault(root, store)) {
            seed.unlock(null, false);
            generation = Json.string(seed.header(), "generation");
            KeyPair pair = Crypto.ecKey();
            JsonObject key = Json.obj("reference", "SOFTWARE");
            key.addProperty("privateKey", Crypto.b64(pair.getPrivate().getEncoded()));
            key.add("publicKey", Crypto.publicJwk(pair.getPublic()));
            seed.update(
                    data -> {
                        data.add("deviceKey", key);
                        data.addProperty("saved", "synthetic-account");
                        return null;
                    });
        }
        unavailable.set(true);
        try (Vault vault = new Vault(root, store);
                MintAuthRuntime runtime =
                        new MintAuthRuntime(
                                new PreparationLifecycleTest.Bridge(),
                                root,
                                vault,
                                PreparationLifecycleTest.localProfile(),
                                false)) {
            runtime.prepareGuidedStorage();
            long first = runtime.submittedOperation();
            PreparationLifecycleTest.await(() -> runtime.completedOperation(first) != null);
            assertFalse(runtime.completedOperation(first).succeeded);
            assertTrue(runtime.needsPassword());
            assertFalse(runtime.canCreatePasswordVault());
            unavailable.set(false);
            runtime.prepareGuidedStorage();
            long retry = runtime.submittedOperation();
            PreparationLifecycleTest.await(() -> runtime.completedOperation(retry) != null);
            assertTrue(runtime.completedOperation(retry).succeeded);
            assertFalse(runtime.needsPassword());
            assertEquals(generation, Json.string(vault.header(), "generation"));
            assertEquals(store.name(), Json.string(vault.header(), "backend"));
            assertEquals("synthetic-account", Json.string(vault.read(), "saved"));
        }
    }

    @Test
    public void newVaultNativeFailureOffersOptionalFallbackWithoutPublishingPasswordVault()
            throws Exception {
        Path root = Files.createTempDirectory("mintauth-native-optional");
        SecretStore store =
                new SecretStore() {
                    public String name() {
                        return "MACOS_KEYCHAIN";
                    }

                    public byte[] read(String generation) throws Exception {
                        throw new IOException("NATIVE_RUNTIME_SOURCE");
                    }

                    public void write(String generation, byte[] key) throws Exception {
                        throw new IOException("NATIVE_RUNTIME_SOURCE");
                    }

                    public void remove(String generation) {}
                };
        try (Vault vault = new Vault(root, store);
                MintAuthRuntime runtime =
                        new MintAuthRuntime(
                                new PreparationLifecycleTest.Bridge(),
                                root,
                                vault,
                                PreparationLifecycleTest.localProfile(),
                                false)) {
            runtime.prepareGuidedStorage();
            long task = runtime.submittedOperation();
            PreparationLifecycleTest.await(() -> runtime.completedOperation(task) != null);
            assertFalse(runtime.completedOperation(task).succeeded);
            assertTrue(runtime.canCreatePasswordVault());
            assertTrue(runtime.storageRecoveryDescription().contains("password is optional"));
            assertNull(vault.header());
        }
    }
}
