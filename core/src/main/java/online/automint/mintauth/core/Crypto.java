// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import com.google.gson.JsonObject;

import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.*;

import javax.crypto.Cipher;
import javax.crypto.spec.*;

public final class Crypto {
    private static final SecureRandom RANDOM = new SecureRandom();

    private Crypto() {}

    public static byte[] random(int size) {
        byte[] value = new byte[size];
        RANDOM.nextBytes(value);
        return value;
    }

    public static String b64(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    public static byte[] unb64(String value) {
        if (value.length() > 240000) throw new IllegalArgumentException("LIMIT");
        return Base64.getUrlDecoder().decode(value);
    }

    public static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String tokenHash(String value) {
        return b64(sha256(value.getBytes(StandardCharsets.US_ASCII)));
    }

    public static byte[] passwordKey(char[] password, byte[] salt) {
        if (password.length < 10 || password.length > 1024 || salt.length != 16)
            throw new IllegalArgumentException("PASSWORD_REQUIREMENTS");
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(
                new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                        .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                        .withMemoryAsKB(65536)
                        .withIterations(3)
                        .withParallelism(1)
                        .withSalt(salt)
                        .build());
        byte[] key = new byte[32];
        generator.generateBytes(password, key);
        return key;
    }

    public static byte[] encrypt(byte[] key, byte[] plaintext, String aad)
            throws GeneralSecurityException {
        byte[] iv = random(12);
        byte[] encrypted;
        if (Cipher.getMaxAllowedKeyLength("AES") < key.length * 8)
            encrypted = portableGcm(true, key, iv, aad.getBytes(StandardCharsets.UTF_8), plaintext);
        else {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, iv));
            cipher.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
            encrypted = cipher.doFinal(plaintext);
        }
        byte[] result = new byte[12 + encrypted.length];
        System.arraycopy(iv, 0, result, 0, 12);
        System.arraycopy(encrypted, 0, result, 12, encrypted.length);
        return result;
    }

    public static byte[] decrypt(byte[] key, byte[] encrypted, String aad)
            throws GeneralSecurityException {
        if (encrypted.length < 28 || encrypted.length > 4 * 1024 * 1024)
            throw new GeneralSecurityException("CIPHER_LIMIT");
        if (Cipher.getMaxAllowedKeyLength("AES") < key.length * 8)
            return portableGcm(
                    false,
                    key,
                    Arrays.copyOf(encrypted, 12),
                    aad.getBytes(StandardCharsets.UTF_8),
                    Arrays.copyOfRange(encrypted, 12, encrypted.length));
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(
                Cipher.DECRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, Arrays.copyOf(encrypted, 12)));
        cipher.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
        return cipher.doFinal(encrypted, 12, encrypted.length - 12);
    }

    static byte[] portableGcm(boolean encrypt, byte[] key, byte[] iv, byte[] aad, byte[] input)
            throws GeneralSecurityException {
        GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
        cipher.init(encrypt, new AEADParameters(new KeyParameter(key), 128, iv, aad));
        byte[] output = new byte[cipher.getOutputSize(input.length)];
        try {
            int count = cipher.processBytes(input, 0, input.length, output, 0);
            count += cipher.doFinal(output, count);
            return Arrays.copyOf(output, count);
        } catch (InvalidCipherTextException error) {
            throw new GeneralSecurityException("GCM_AUTHENTICATION", error);
        } finally {
            Arrays.fill(output, (byte) 0);
        }
    }

    public static KeyPair ecKey() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"), RANDOM);
        return generator.generateKeyPair();
    }

    private static byte[] unsigned32(BigInteger value) {
        byte[] raw = value.toByteArray(), result = new byte[32];
        int size = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - size, result, 32 - size, size);
        return result;
    }

    public static JsonObject publicJwk(PublicKey key) {
        ECPublicKey ec = (ECPublicKey) key;
        JsonObject result = new JsonObject();
        result.addProperty("kty", "EC");
        result.addProperty("crv", "P-256");
        result.addProperty("x", b64(unsigned32(ec.getW().getAffineX())));
        result.addProperty("y", b64(unsigned32(ec.getW().getAffineY())));
        return result;
    }

    public static PublicKey publicKey(JsonObject jwk) throws GeneralSecurityException {
        if (!"EC".equals(Json.string(jwk, "kty"))
                || !"P-256".equals(Json.string(jwk, "crv"))
                || jwk.has("d")) throw new GeneralSecurityException("KEY_INVALID");
        byte[] x = unb64(Json.string(jwk, "x")), y = unb64(Json.string(jwk, "y"));
        if (x.length != 32 || y.length != 32) throw new GeneralSecurityException("KEY_INVALID");
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1"));
        return KeyFactory.getInstance("EC")
                .generatePublic(
                        new ECPublicKeySpec(
                                new ECPoint(new BigInteger(1, x), new BigInteger(1, y)),
                                params.getParameterSpec(ECParameterSpec.class)));
    }

    public static PrivateKey privateKey(String encoded) throws GeneralSecurityException {
        return KeyFactory.getInstance("EC")
                .generatePrivate(new PKCS8EncodedKeySpec(unb64(encoded)));
    }

    public interface Signer {
        JsonObject publicJwk();

        byte[] sign(byte[] message) throws GeneralSecurityException;

        String reference();
    }

    public static Signer software(final PrivateKey key, final JsonObject jwk) {
        return new Signer() {
            public JsonObject publicJwk() {
                return jwk.deepCopy();
            }

            public String reference() {
                return "SOFTWARE";
            }

            public byte[] sign(byte[] message) throws GeneralSecurityException {
                Signature s = Signature.getInstance("SHA256withECDSA");
                s.initSign(key);
                s.update(message);
                return joseSignature(s.sign());
            }
        };
    }

    public static byte[] joseSignature(byte[] der) throws GeneralSecurityException {
        try {
            ASN1Sequence sequence = ASN1Sequence.getInstance(der);
            if (sequence.size() != 2) throw new Exception();
            byte[]
                    r =
                            unsigned32(
                                    ASN1Integer.getInstance(sequence.getObjectAt(0))
                                            .getPositiveValue()),
                    s =
                            unsigned32(
                                    ASN1Integer.getInstance(sequence.getObjectAt(1))
                                            .getPositiveValue());
            byte[] result = new byte[64];
            System.arraycopy(r, 0, result, 0, 32);
            System.arraycopy(s, 0, result, 32, 32);
            return result;
        } catch (Exception e) {
            throw new GeneralSecurityException("SIGNATURE_INVALID");
        }
    }

    public static byte[] derSignature(byte[] jose) throws GeneralSecurityException {
        if (jose.length != 64) throw new GeneralSecurityException("SIGNATURE_INVALID");
        try {
            return new DERSequence(
                            new ASN1Encodable[] {
                                new ASN1Integer(new BigInteger(1, Arrays.copyOfRange(jose, 0, 32))),
                                new ASN1Integer(new BigInteger(1, Arrays.copyOfRange(jose, 32, 64)))
                            })
                    .getEncoded();
        } catch (Exception e) {
            throw new GeneralSecurityException("SIGNATURE_INVALID");
        }
    }

    public static String proof(
            Signer signer, String method, String url, String credential, String nonce)
            throws GeneralSecurityException {
        JsonObject header = new JsonObject();
        header.addProperty("typ", "dpop+jwt");
        header.addProperty("alg", "ES256");
        header.add("jwk", signer.publicJwk());
        JsonObject payload = new JsonObject();
        payload.addProperty("jti", UUID.randomUUID().toString());
        payload.addProperty("htm", method);
        payload.addProperty("htu", url);
        payload.addProperty("iat", System.currentTimeMillis() / 1000);
        if (credential != null) payload.addProperty("ath", tokenHash(credential));
        if (nonce != null) payload.addProperty("nonce", nonce);
        String input =
                b64(Json.GSON.toJson(header).getBytes(StandardCharsets.UTF_8))
                        + "."
                        + b64(Json.GSON.toJson(payload).getBytes(StandardCharsets.UTF_8));
        return input + "." + b64(signer.sign(input.getBytes(StandardCharsets.US_ASCII)));
    }

    public static JsonObject decryptEnvelope(String jwe, PrivateKey privateKey, String binding)
            throws GeneralSecurityException {
        if (jwe.length() > 160000) throw new GeneralSecurityException("ENVELOPE_LIMIT");
        String[] p = jwe.split("\\.", -1);
        if (p.length != 5) throw new GeneralSecurityException("ENVELOPE_INVALID");
        JsonObject header = Json.object(new String(unb64(p[0]), StandardCharsets.UTF_8), 8192);
        if (!"RSA-OAEP-256".equals(Json.string(header, "alg"))
                || !"A256GCM".equals(Json.string(header, "enc"))
                || !"automint-autosec+jwe".equals(Json.string(header, "typ"))
                || !binding.equals(Json.string(header, "am")))
            throw new GeneralSecurityException("ENVELOPE_BINDING");
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
        rsa.init(
                Cipher.DECRYPT_MODE,
                privateKey,
                new OAEPParameterSpec(
                        "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        byte[] key = rsa.doFinal(unb64(p[1])),
                iv = unb64(p[2]),
                tag = unb64(p[4]),
                ct = unb64(p[3]),
                plain = null;
        try {
            if (key.length != 32 || iv.length != 12 || tag.length != 16)
                throw new GeneralSecurityException("ENVELOPE_INVALID");
            byte[] combined = new byte[ct.length + 16];
            System.arraycopy(ct, 0, combined, 0, ct.length);
            System.arraycopy(tag, 0, combined, ct.length, 16);
            Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
            aes.init(
                    Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, iv));
            aes.updateAAD(p[0].getBytes(StandardCharsets.US_ASCII));
            plain = aes.doFinal(combined);
            return Json.object(new String(plain, StandardCharsets.UTF_8), 100000);
        } finally {
            Arrays.fill(key, (byte) 0);
            if (plain != null) Arrays.fill(plain, (byte) 0);
        }
    }
}
