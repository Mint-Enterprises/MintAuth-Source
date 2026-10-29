// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import static org.junit.Assert.*;

import org.junit.Assume;
import org.junit.Test;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.spec.*;

public class PortableCryptoTest {
    @Test
    public void aes256MatchesJceWireFormat() throws Exception {
        Assume.assumeTrue(Cipher.getMaxAllowedKeyLength("AES") >= 256);
        byte[] key = new byte[32], iv = new byte[12], aad = {1, 2, 3}, plain = {4, 5, 6, 7};
        Cipher jce = Cipher.getInstance("AES/GCM/NoPadding");
        jce.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        jce.updateAAD(aad);
        byte[] expected = jce.doFinal(plain);
        assertArrayEquals(expected, Crypto.portableGcm(true, key, iv, aad, plain));
        assertArrayEquals(plain, Crypto.portableGcm(false, key, iv, aad, expected));
    }

    @Test
    public void tamperedCiphertextAndContextAreRejected() throws Exception {
        byte[] key = new byte[32], iv = new byte[12], aad = {1}, plain = {4, 5, 6};
        byte[] cipher = Crypto.portableGcm(true, key, iv, aad, plain);
        assertArrayEquals(plain, Crypto.portableGcm(false, key, iv, aad, cipher));
        byte[] altered = cipher.clone();
        altered[0] ^= 1;
        reject(key, iv, aad, altered);
        reject(key, iv, new byte[] {2}, cipher);
    }

    private static void reject(byte[] key, byte[] iv, byte[] aad, byte[] ciphertext)
            throws Exception {
        try {
            Crypto.portableGcm(false, key, iv, aad, ciphertext);
            fail("Authentication required");
        } catch (GeneralSecurityException expected) {
            assertEquals("GCM_AUTHENTICATION", expected.getMessage());
        }
    }

    @Test
    public void publicApiWorksOnRestrictedAndUnrestrictedRuntimes() throws Exception {
        byte[] key = new byte[32], data = {9, 8, 7};
        byte[] cipher = Crypto.encrypt(key, data, "synthetic-test-context");
        assertArrayEquals(data, Crypto.decrypt(key, cipher, "synthetic-test-context"));
        try {
            Crypto.decrypt(key, cipher, "wrong-context");
            fail("Context must be authenticated");
        } catch (GeneralSecurityException expected) {
        }
    }
}
