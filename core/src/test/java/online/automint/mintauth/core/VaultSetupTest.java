// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import static org.junit.Assert.*;

import org.junit.Test;

import java.nio.file.*;

public class VaultSetupTest {
    @Test
    public void existingNonFileHeaderDoesNotCreateAReplacementVault() throws Exception {
        Path root = Files.createTempDirectory("mintauth-header-not-file");
        Files.createDirectory(root.resolve("header.json"));
        try (Vault vault = new Vault(root, new SecurityTest.MemoryStore())) {
            try {
                vault.unlock(null, false);
                fail();
            } catch (java.io.IOException expected) {
            }
            assertTrue(Files.isDirectory(root.resolve("header.json")));
            try (java.util.stream.Stream<Path> files = Files.list(root)) {
                assertFalse(files.anyMatch(path -> path.getFileName().toString().endsWith(".enc")));
            }
        }
    }

    @Test
    public void nativeFailureOffersRecoveryWithoutPublishingOrReplacingVaults() throws Exception {
        Path root = Files.createTempDirectory("mintauth-native-failure");
        SecurityTest.MemoryStore backing = new SecurityTest.MemoryStore();
        SecretStore unavailable =
                new SecretStore() {
                    public String name() {
                        return backing.name();
                    }

                    public byte[] read(String generation) {
                        throw new NoSuchMethodError("synthetic native conflict");
                    }

                    public void write(String generation, byte[] key) {
                        throw new NoSuchMethodError("synthetic native conflict");
                    }

                    public void remove(String generation) {}
                };
        try (Vault first = new Vault(root, unavailable)) {
            try {
                first.unlock(null, false);
                fail("Native failure must be reported");
            } catch (Vault.Locked expected) {
                assertEquals("OS_STORE_UNAVAILABLE", expected.getMessage());
            }
            assertNull(first.header());
        }
        String generation;
        try (Vault existing = new Vault(root, backing)) {
            existing.unlock(null, false);
            generation = Json.string(existing.header(), "generation");
            existing.update(
                    data -> {
                        data.addProperty("synthetic-saved-entry", true);
                        return null;
                    });
        }
        try (Vault locked = new Vault(root, unavailable)) {
            try {
                locked.unlock(null, false);
                fail("Existing key unavailable");
            } catch (Vault.Locked expected) {
                assertEquals("OS_STORE_UNAVAILABLE", expected.getMessage());
            }
            assertEquals(generation, Json.string(locked.header(), "generation"));
        }
        try (Vault recovery = new Vault(root, backing)) {
            recovery.unlock(null, false);
            assertTrue(recovery.read().get("synthetic-saved-entry").getAsBoolean());
            assertEquals(generation, Json.string(recovery.header(), "generation"));
        }
    }

    @Test
    public void failedFirstSaveDoesNotPublishAnUnusableHeader() throws Exception {
        Path root = Files.createTempDirectory("mintauth-failed-setup");
        SecurityTest.MemoryStore delegate = new SecurityTest.MemoryStore();
        SecretStore failing =
                new SecretStore() {
                    public String name() {
                        return "TEST";
                    }

                    public byte[] read(String generation) {
                        return delegate.read(generation);
                    }

                    public void write(String generation, byte[] key) throws Exception {
                        delegate.write(generation, key);
                        Files.createDirectory(root.resolve("vault-" + generation + ".enc"));
                    }

                    public void remove(String generation) {
                        delegate.remove(generation);
                    }
                };
        try (Vault vault = new Vault(root, failing)) {
            try {
                vault.unlock(null, false);
                fail("Save should fail");
            } catch (Vault.Locked expected) {
            }
            assertNull(vault.header());
        }
        try (Vault retry = new Vault(root, new SecurityTest.MemoryStore())) {
            retry.unlock(null, false);
            assertNotNull(retry.header());
            assertTrue(retry.read().entrySet().isEmpty());
        }
    }
}
