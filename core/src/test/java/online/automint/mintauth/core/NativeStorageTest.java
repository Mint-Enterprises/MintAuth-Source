// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import static org.junit.Assert.*;

import org.junit.Assume;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.Signature;
import java.util.*;

public class NativeStorageTest {
    @Test
    public void windowsVaultRootUsesTheOperatingSystemKnownFolder() throws Exception {
        Assume.assumeTrue(System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win"));
        assertEquals(Paths.get(NativeStores.windowsDataRoot(), "MintAuth"), Vault.defaultRoot());
        assertTrue(Paths.get(NativeStores.windowsDataRoot()).isAbsolute());
    }

    @Test
    public void macKeychainRoundTripAndDeletion() throws Exception {
        String os = System.getProperty("os.name").toLowerCase(Locale.ROOT);
        Assume.assumeTrue(os.contains("mac") || os.contains("darwin"));
        SecretStore store =
                NativeStores.forPlatform(Files.createTempDirectory("mintauth-mac-store"));
        String generation = UUID.randomUUID().toString();
        byte[] key = Crypto.random(32);
        try {
            store.write(generation, key);
            assertArrayEquals(key, store.read(generation));
            store.remove(generation);
            store.remove(generation);
            assertNull(store.read(generation));
        } finally {
            Arrays.fill(key, (byte) 0);
            store.remove(generation);
        }
    }

    @Test
    public void windowsDpapiRoundTripAndDeletion() throws Exception {
        Assume.assumeTrue(System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win"));
        Path root = Files.createTempDirectory("mintauth-native-test");
        SecretStore store = NativeStores.forPlatform(root);
        String generation = UUID.randomUUID().toString();
        byte[] key = Crypto.random(32);
        try {
            store.write(generation, key);
            assertArrayEquals(key, store.read(generation));
            byte[] cipher =
                    Files.readAllBytes(root.resolve("mintauth-master-" + generation + ".dpapi"));
            assertFalse(Arrays.equals(key, cipher));
            store.remove(generation);
            store.remove(generation);
            assertFalse(Files.exists(root.resolve("mintauth-master-" + generation + ".dpapi")));
        } finally {
            Arrays.fill(key, (byte) 0);
            store.remove(generation);
        }
    }

    @Test
    public void availableHardwareKeySignsAndDeletesIdempotently() throws Exception {
        String generation = UUID.randomUUID().toString();
        Crypto.Signer key = HardwareKeys.create(generation);
        Assume.assumeNotNull(key);
        String reference = key.reference();
        try {
            byte[] message =
                    "MintAuth synthetic hardware-key check".getBytes(StandardCharsets.UTF_8);
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(Crypto.publicKey(key.publicJwk()));
            verifier.update(message);
            assertTrue(verifier.verify(Crypto.derSignature(key.sign(message))));
        } finally {
            if (key instanceof AutoCloseable) ((AutoCloseable) key).close();
            HardwareKeys.remove(reference);
            HardwareKeys.remove(reference);
        }
        try {
            HardwareKeys.open(reference);
            fail();
        } catch (java.security.GeneralSecurityException expected) {
        }
    }
}
