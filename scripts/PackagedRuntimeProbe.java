// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.probe;

import online.automint.mintauth.core.Crypto;
import online.automint.mintauth.core.NativeStores;
import online.automint.mintauth.core.ReleaseVerifier;
import online.automint.mintauth.core.SecretStore;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.*;

public final class PackagedRuntimeProbe {
    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }

    public static void main(String[] args) throws Exception {
        byte[] key = new byte[32], iv = new byte[12], aad = {1,2,3}, plain = {4,5,6};
        Method portable = Crypto.class.getDeclaredMethod("portableGcm", boolean.class,
                byte[].class, byte[].class, byte[].class, byte[].class);
        portable.setAccessible(true);
        byte[] cipher = (byte[]) portable.invoke(null, true, key, iv, aad, plain);
        check(Arrays.equals(plain, (byte[]) portable.invoke(null, false, key, iv, aad, cipher)), "Portable AES-GCM round trip");
        if (Cipher.getMaxAllowedKeyLength("AES") >= 256) {
            Cipher jce = Cipher.getInstance("AES/GCM/NoPadding");
            jce.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            jce.updateAAD(aad);
            check(Arrays.equals(cipher, jce.doFinal(plain)), "Portable AES-256 wire format");
        }
        cipher[0] ^= 1;
        try { portable.invoke(null, false, key, iv, aad, cipher); throw new AssertionError("Tampered GCM accepted"); }
        catch (InvocationTargetException expected) { check(expected.getCause() instanceof GeneralSecurityException, "GCM authentication"); }
        byte[] encrypted = Crypto.encrypt(key, plain, "synthetic-packaged-probe");
        check(Arrays.equals(plain, Crypto.decrypt(key, encrypted, "synthetic-packaged-probe")), "Vault AES-GCM");
        char[] password = "synthetic-packaged-probe-password".toCharArray();
        byte[] salt = new byte[16];
        byte[] derived = Crypto.passwordKey(password, salt);
        check(derived.length == 32 && Arrays.equals(derived, Crypto.passwordKey(password, salt)), "Argon2id");
        Arrays.fill(password, '\0'); Arrays.fill(derived, (byte) 0);
        KeyPair ec = Crypto.ecKey();
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(ec.getPrivate()); ecdsa.update(plain);
        byte[] signature = ecdsa.sign();
        Method der = Crypto.class.getMethod("derSignature", byte[].class);
        byte[] roundTrip = (byte[]) der.invoke(null, (Object) Crypto.joseSignature(signature));
        ecdsa.initVerify(ec.getPublic()); ecdsa.update(plain);
        check(ecdsa.verify(roundTrip), "P-256 DER/JOSE signatures");
        ReleaseVerifier verifier = new ReleaseVerifier();
        if (args.length == 2) {
            byte[] manifest = Files.readAllBytes(Paths.get(args[0]));
            String signed = new String(Files.readAllBytes(Paths.get(args[1])), StandardCharsets.US_ASCII).trim();
            ReleaseVerifier.Release release = verifier.verify(manifest, signed);
            Path ownJar = Paths.get(Crypto.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            boolean verifiedJar = false;
            for (String target : Arrays.asList("forge-1.8.9", "fabric-1.21.11", "fabric-26.3")) {
                if (ownJar.getFileName().toString().startsWith("mintauth-" + target + "-")) {
                    verifier.verifyJar(ownJar, target, release.artifact(target), release.commit);
                    verifiedJar = true;
                }
            }
            check(verifiedJar, "Signed JAR target binding");
            manifest[0] ^= 1;
            try { verifier.verify(manifest, signed); throw new AssertionError("Tampered release accepted"); }
            catch (java.io.IOException expected) { check("UPDATE_SIGNATURE".equals(expected.getMessage()), "Ed25519 rejection"); }
        }
        for (String resource : Arrays.asList("com/sun/jna/win32-x86-64/jnidispatch.dll",
                "com/sun/jna/linux-x86-64/libjnidispatch.so", "com/sun/jna/darwin-x86-64/libjnidispatch.jnilib",
                "com/sun/jna/darwin-aarch64/libjnidispatch.jnilib"))
            check(PackagedRuntimeProbe.class.getClassLoader().getResource(resource) != null, "Missing supported native");
        Method loadNative = Class.forName("online.automint.mintauth.core.NativeRuntime").getDeclaredMethod("loader");
        loadNative.setAccessible(true);
        ClassLoader isolated = (ClassLoader) loadNative.invoke(null);
        Class<?> memoryType = Class.forName("com.sun.jna.Memory", true, isolated);
        Object memory = memoryType.getConstructor(long.class).newInstance(8L);
        try {
            memoryType.getMethod("setLong", long.class, long.class).invoke(memory, 0L, 123456789L);
            check(Long.valueOf(123456789L).equals(memoryType.getMethod("getLong", long.class).invoke(memory, 0L)), "Isolated native dispatch");
        } finally { memoryType.getMethod("close").invoke(memory); }
        Path temp = Files.createTempDirectory("mintauth-packaged-probe-");
        try {
            SecretStore store = NativeStores.forPlatform(temp);
            check(store.name().length() > 0, "Isolated JNA initialization");
            if (System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win")) {
                String generation = UUID.randomUUID().toString();
                try { store.write(generation, key); check(Arrays.equals(key, store.read(generation)), "Packaged DPAPI"); }
                finally { store.remove(generation); }
            }
        } finally { Files.delete(temp); }
        System.out.println("Packaged runtime passed: AES-256/GCM, tamper rejection, Argon2id, P-256, release key, "
                + (args.length == 2 ? "Ed25519/pinned signed JAR, " : "")
                + "native resources and isolated JNA");
    }
}
