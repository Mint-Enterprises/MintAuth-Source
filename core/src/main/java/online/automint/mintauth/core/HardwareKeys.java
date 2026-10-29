// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import com.google.gson.JsonObject;
import com.sun.jna.*;
import com.sun.jna.ptr.*;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

public final class HardwareKeys {
    private HardwareKeys() {}

    public static Crypto.Signer create(String generation) {
        if (!NativeRuntime.owns(HardwareKeys.class)) return NativeRuntime.createKey(generation);
        try {
            String os = System.getProperty("os.name").toLowerCase(Locale.ROOT);
            if (os.contains("mac") || os.contains("darwin")) return new Enclave(generation, true);
            if (os.contains("win")) return new Cng(generation, true);
        } catch (Exception | LinkageError ignored) {
        }
        return null;
    }

    public static Crypto.Signer open(String reference) throws GeneralSecurityException {
        if (!NativeRuntime.owns(HardwareKeys.class)) return NativeRuntime.openKey(reference);
        try {
            String[] parts = reference.split(":", 2);
            if (parts.length != 2) throw new Exception();
            if (parts[0].equals("CNG_TPM")) return new Cng(parts[1], false);
            if (parts[0].equals("SECURE_ENCLAVE")) return new Enclave(parts[1], false);
        } catch (Exception | LinkageError e) {
            throw new GeneralSecurityException("ENROLLED_KEY_UNAVAILABLE");
        }
        throw new GeneralSecurityException("ENROLLED_KEY_UNAVAILABLE");
    }

    public static void remove(String reference) throws Exception {
        if (!NativeRuntime.owns(HardwareKeys.class)) {
            NativeRuntime.removeKey(reference);
            return;
        }
        if (reference.startsWith("CNG_TPM:")) {
            String generation = UUID.fromString(reference.substring(8)).toString();
            NCrypt api = Native.load("ncrypt", NCrypt.class);
            PointerByReference provider = new PointerByReference(), key = new PointerByReference();
            if (api.NCryptOpenStorageProvider(
                            provider, new WString("Microsoft Platform Crypto Provider"), 0)
                    != 0) throw new GeneralSecurityException("KEY_DELETE_FAILED");
            try {
                int status =
                        api.NCryptOpenKey(
                                provider.getValue(),
                                key,
                                new WString("MintAuth-" + generation),
                                0,
                                0x40);
                if (status == 0x80090016 || status == 0x80090011) return;
                if (status != 0) throw new GeneralSecurityException("KEY_DELETE_FAILED");
                if (api.NCryptDeleteKey(key.getValue(), 0) != 0)
                    throw new GeneralSecurityException("KEY_DELETE_FAILED");
                key.setValue(null);
            } finally {
                if (key.getValue() != null) api.NCryptFreeObject(key.getValue());
                api.NCryptFreeObject(provider.getValue());
            }
        } else if (reference.startsWith("SECURE_ENCLAVE:")) {
            Enclave key = new Enclave(reference.substring(15));
            Pointer query = key.query(false);
            try {
                int status = key.security.SecItemDelete(query);
                if (status != 0 && status != -25300)
                    throw new GeneralSecurityException("KEY_DELETE_FAILED");
            } finally {
                key.cf.CFRelease(query);
            }
        } else throw new GeneralSecurityException("KEY_REFERENCE");
    }

    interface NCrypt extends Library {
        int NCryptOpenStorageProvider(PointerByReference provider, WString name, int flags);

        int NCryptCreatePersistedKey(
                Pointer provider,
                PointerByReference key,
                WString algorithm,
                WString name,
                int legacy,
                int flags);

        int NCryptFinalizeKey(Pointer key, int flags);

        int NCryptOpenKey(
                Pointer provider, PointerByReference key, WString name, int legacy, int flags);

        int NCryptExportKey(
                Pointer key,
                Pointer exportKey,
                WString blobType,
                Pointer parameters,
                byte[] output,
                int outputSize,
                IntByReference result,
                int flags);

        int NCryptSignHash(
                Pointer key,
                Pointer padding,
                byte[] hash,
                int hashLength,
                byte[] output,
                int outputSize,
                IntByReference result,
                int flags);

        int NCryptDeleteKey(Pointer key, int flags);

        int NCryptFreeObject(Pointer handle);
    }

    static final class Cng implements Crypto.Signer, AutoCloseable {
        final NCrypt api = Native.load("ncrypt", NCrypt.class);
        Pointer provider, key;
        final String generation;
        final JsonObject jwk;

        void check(int status) throws GeneralSecurityException {
            if (status != 0) throw new GeneralSecurityException("TPM_KEY_UNAVAILABLE");
        }

        Cng(String generation, boolean create) throws Exception {
            this.generation = UUID.fromString(generation).toString();
            PointerByReference p = new PointerByReference(), k = new PointerByReference();
            check(
                    api.NCryptOpenStorageProvider(
                            p, new WString("Microsoft Platform Crypto Provider"), 0));
            provider = p.getValue();
            try {
                if (create) {
                    check(
                            api.NCryptCreatePersistedKey(
                                    provider,
                                    k,
                                    new WString("ECDSA_P256"),
                                    new WString("MintAuth-" + this.generation),
                                    0,
                                    0));
                    key = k.getValue();
                    check(api.NCryptFinalizeKey(key, 0));
                } else {
                    check(
                            api.NCryptOpenKey(
                                    provider,
                                    k,
                                    new WString("MintAuth-" + this.generation),
                                    0,
                                    0x40));
                    key = k.getValue();
                }
                byte[] blob = new byte[72];
                IntByReference length = new IntByReference();
                check(
                        api.NCryptExportKey(
                                key,
                                null,
                                new WString("ECCPUBLICBLOB"),
                                null,
                                blob,
                                blob.length,
                                length,
                                0));
                if (length.getValue() != 72
                        || blob[0] != 'E'
                        || blob[1] != 'C'
                        || blob[2] != 'S'
                        || blob[3] != '1') throw new GeneralSecurityException("KEY_INVALID");
                jwk = new JsonObject();
                jwk.addProperty("kty", "EC");
                jwk.addProperty("crv", "P-256");
                jwk.addProperty("x", Crypto.b64(Arrays.copyOfRange(blob, 8, 40)));
                jwk.addProperty("y", Crypto.b64(Arrays.copyOfRange(blob, 40, 72)));
            } catch (Exception e) {
                close();
                throw e;
            }
        }

        public JsonObject publicJwk() {
            return jwk.deepCopy();
        }

        public String reference() {
            return "CNG_TPM:" + generation;
        }

        public synchronized byte[] sign(byte[] message) throws GeneralSecurityException {
            byte[] out = new byte[64], hash = Crypto.sha256(message);
            IntByReference size = new IntByReference();
            check(api.NCryptSignHash(key, null, hash, hash.length, out, out.length, size, 0x40));
            if (size.getValue() != 64) throw new GeneralSecurityException("SIGNATURE_INVALID");
            return out;
        }

        public void close() {
            if (key != null) {
                api.NCryptFreeObject(key);
                key = null;
            }
            if (provider != null) {
                api.NCryptFreeObject(provider);
                provider = null;
            }
        }
    }

    interface CoreFoundation extends Library {
        Pointer CFDictionaryCreateMutable(
                Pointer allocator, long capacity, Pointer keyCallbacks, Pointer valueCallbacks);

        void CFDictionarySetValue(Pointer dictionary, Pointer key, Pointer value);

        Pointer CFNumberCreate(Pointer allocator, int type, Pointer value);

        Pointer CFDataCreate(Pointer allocator, byte[] bytes, long length);

        long CFDataGetLength(Pointer data);

        Pointer CFDataGetBytePtr(Pointer data);

        void CFRelease(Pointer value);
    }

    interface Sec extends Library {
        Pointer SecKeyCreateRandomKey(Pointer attributes, PointerByReference error);

        Pointer SecKeyCopyPublicKey(Pointer key);

        Pointer SecKeyCopyExternalRepresentation(Pointer key, PointerByReference error);

        Pointer SecKeyCreateSignature(
                Pointer key, Pointer algorithm, Pointer message, PointerByReference error);

        Pointer SecAccessControlCreateWithFlags(
                Pointer allocator, Pointer protection, long flags, PointerByReference error);

        int SecItemCopyMatching(Pointer query, PointerByReference result);

        int SecItemDelete(Pointer query);
    }

    static final class Enclave implements Crypto.Signer, AutoCloseable {
        final NativeLibrary secLib = NativeLibrary.getInstance("Security"),
                cfLib = NativeLibrary.getInstance("CoreFoundation");
        final Sec security = Native.load("Security", Sec.class);
        final CoreFoundation cf = Native.load("CoreFoundation", CoreFoundation.class);
        final String generation;
        Pointer key;
        JsonObject jwk;

        Pointer constant(String name) {
            return (name.startsWith("kCF") ? cfLib : secLib)
                    .getGlobalVariableAddress(name)
                    .getPointer(0);
        }

        Pointer dictionary() {
            return cf.CFDictionaryCreateMutable(
                    null,
                    0,
                    cfLib.getGlobalVariableAddress("kCFTypeDictionaryKeyCallBacks"),
                    cfLib.getGlobalVariableAddress("kCFTypeDictionaryValueCallBacks"));
        }

        Pointer tag() {
            byte[] tag =
                    ("online.automint.mintauth." + generation).getBytes(StandardCharsets.UTF_8);
            return cf.CFDataCreate(null, tag, tag.length);
        }

        Pointer query(boolean returning) {
            Pointer query = dictionary(), tag = tag();
            cf.CFDictionarySetValue(query, constant("kSecClass"), constant("kSecClassKey"));
            cf.CFDictionarySetValue(query, constant("kSecAttrApplicationTag"), tag);
            cf.CFDictionarySetValue(
                    query, constant("kSecAttrTokenID"), constant("kSecAttrTokenIDSecureEnclave"));
            if (returning)
                cf.CFDictionarySetValue(
                        query, constant("kSecReturnRef"), constant("kCFBooleanTrue"));
            cf.CFRelease(tag);
            return query;
        }

        Enclave(String generation) {
            this.generation = UUID.fromString(generation).toString();
        }

        Enclave(String generation, boolean create) throws Exception {
            this(generation);
            PointerByReference error = new PointerByReference();
            if (create) {
                Pointer attributes = dictionary(),
                        privateAttrs = dictionary(),
                        tag = tag(),
                        number = cf.CFNumberCreate(null, 9, new IntByReference(256).getPointer());
                Pointer access =
                        security.SecAccessControlCreateWithFlags(
                                null,
                                constant("kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly"),
                                1L << 30,
                                error);
                try {
                    if (access == null) throw new GeneralSecurityException("ENCLAVE_UNAVAILABLE");
                    cf.CFDictionarySetValue(
                            attributes,
                            constant("kSecAttrKeyType"),
                            constant("kSecAttrKeyTypeECSECPrimeRandom"));
                    cf.CFDictionarySetValue(attributes, constant("kSecAttrKeySizeInBits"), number);
                    cf.CFDictionarySetValue(
                            attributes,
                            constant("kSecAttrTokenID"),
                            constant("kSecAttrTokenIDSecureEnclave"));
                    cf.CFDictionarySetValue(
                            privateAttrs,
                            constant("kSecAttrIsPermanent"),
                            constant("kCFBooleanTrue"));
                    cf.CFDictionarySetValue(privateAttrs, constant("kSecAttrApplicationTag"), tag);
                    cf.CFDictionarySetValue(
                            privateAttrs, constant("kSecAttrAccessControl"), access);
                    cf.CFDictionarySetValue(
                            attributes, constant("kSecPrivateKeyAttrs"), privateAttrs);
                    key = security.SecKeyCreateRandomKey(attributes, error);
                } finally {
                    if (access != null) cf.CFRelease(access);
                    cf.CFRelease(attributes);
                    cf.CFRelease(privateAttrs);
                    cf.CFRelease(tag);
                    cf.CFRelease(number);
                    if (error.getValue() != null) {
                        cf.CFRelease(error.getValue());
                        error.setValue(null);
                    }
                }
            } else {
                Pointer q = query(true);
                PointerByReference result = new PointerByReference();
                try {
                    if (security.SecItemCopyMatching(q, result) != 0)
                        throw new GeneralSecurityException("ENROLLED_KEY_UNAVAILABLE");
                    key = result.getValue();
                } finally {
                    cf.CFRelease(q);
                }
            }
            if (key == null) throw new GeneralSecurityException("ENCLAVE_UNAVAILABLE");
            Pointer pub = security.SecKeyCopyPublicKey(key),
                    data = security.SecKeyCopyExternalRepresentation(pub, error);
            try {
                if (data == null || cf.CFDataGetLength(data) != 65)
                    throw new GeneralSecurityException("KEY_INVALID");
                byte[] raw = cf.CFDataGetBytePtr(data).getByteArray(0, 65);
                if (raw[0] != 4) throw new GeneralSecurityException("KEY_INVALID");
                jwk = new JsonObject();
                jwk.addProperty("kty", "EC");
                jwk.addProperty("crv", "P-256");
                jwk.addProperty("x", Crypto.b64(Arrays.copyOfRange(raw, 1, 33)));
                jwk.addProperty("y", Crypto.b64(Arrays.copyOfRange(raw, 33, 65)));
            } finally {
                if (data != null) cf.CFRelease(data);
                if (pub != null) cf.CFRelease(pub);
                if (error.getValue() != null) cf.CFRelease(error.getValue());
            }
        }

        public JsonObject publicJwk() {
            return jwk.deepCopy();
        }

        public String reference() {
            return "SECURE_ENCLAVE:" + generation;
        }

        public synchronized byte[] sign(byte[] message) throws GeneralSecurityException {
            Pointer input = cf.CFDataCreate(null, message, message.length);
            PointerByReference error = new PointerByReference();
            Pointer result = null;
            try {
                result =
                        security.SecKeyCreateSignature(
                                key,
                                constant("kSecKeyAlgorithmECDSASignatureMessageX962SHA256"),
                                input,
                                error);
                if (result == null) throw new GeneralSecurityException("ENCLAVE_SIGN_FAILED");
                long size = cf.CFDataGetLength(result);
                if (size > 256) throw new GeneralSecurityException("SIGNATURE_INVALID");
                return Crypto.joseSignature(
                        cf.CFDataGetBytePtr(result).getByteArray(0, (int) size));
            } finally {
                cf.CFRelease(input);
                if (result != null) cf.CFRelease(result);
                if (error.getValue() != null) cf.CFRelease(error.getValue());
            }
        }

        public void close() {
            if (key != null) {
                cf.CFRelease(key);
                key = null;
            }
        }
    }
}
