// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import com.google.gson.*;

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.internal.asn1.edec.EdECObjectIdentifiers;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;
import java.util.jar.*;

public final class ReleaseVerifier {
    public static final int MAX_JAR = 32 * 1024 * 1024;
    private static final String[] TARGETS = {"forge-1.8.9", "fabric-1.21.11", "fabric-26.3"};
    private final Ed25519PublicKeyParameters publicKey;
    private FlowDiagnostics trace = FlowDiagnostics.silent();

    ReleaseVerifier withDiagnostics(FlowDiagnostics value) {
        trace = value;
        return this;
    }

    private final String certificateHash;

    public static final class Release {
        public final byte[] bytes;
        public final String signature, commit, channel, id;
        public final long createdAt;
        private final Map<String, Artifact> files;

        Release(byte[] bytes, String signature, JsonObject value, Map<String, Artifact> files) {
            this.bytes = bytes.clone();
            this.signature = signature;
            this.files = files;
            commit = Json.string(value, "commit");
            channel = Json.string(value, "channel");
            createdAt = Instant.parse(Json.string(value, "createdAt")).toEpochMilli();
            id = hex(Crypto.sha256(bytes));
        }

        public Artifact artifact(String target) throws IOException {
            Artifact file = files.get(target);
            if (file == null) throw new IOException("UPDATE_TARGET");
            return file;
        }
    }

    public static final class Artifact {
        public final String target, name, sha256;
        public final int size;

        Artifact(String target, String name, String sha256, int size) {
            this.target = target;
            this.name = name;
            this.sha256 = sha256;
            this.size = size;
        }
    }

    public ReleaseVerifier() throws Exception {
        this(resource("release-public.pub"), resource("jar-signing.crt"));
    }

    ReleaseVerifier(byte[] publicPem, byte[] certificate) throws Exception {
        String pem =
                new String(publicPem, StandardCharsets.US_ASCII)
                        .replace("-----BEGIN PUBLIC KEY-----", "")
                        .replace("-----END PUBLIC KEY-----", "")
                        .replaceAll("\\s", "");
        SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(Base64.getDecoder().decode(pem));
        if (!EdECObjectIdentifiers.id_Ed25519.equals(info.getAlgorithm().getAlgorithm())
                || info.getAlgorithm().getParameters() != null
                || info.getPublicKeyData().getPadBits() != 0)
            throw new IOException("UPDATE_KEY");
        byte[] encodedKey = info.getPublicKeyData().getOctets();
        if (encodedKey.length != Ed25519PublicKeyParameters.KEY_SIZE) throw new IOException("UPDATE_KEY");
        publicKey = new Ed25519PublicKeyParameters(encodedKey, 0);
        X509Certificate cert =
                (X509Certificate)
                        CertificateFactory.getInstance("X.509")
                                .generateCertificate(new ByteArrayInputStream(certificate));
        certificateHash = hex(Crypto.sha256(cert.getEncoded()));
    }

    public Release verify(JsonObject envelope) throws Exception {
        trace.step(FlowDiagnostics.Step.UPDATE_MANIFEST_VERIFY, FlowDiagnostics.Result.STARTED);
        try {
            Release result = verifyInternal(envelope);
            trace.step(
                    FlowDiagnostics.Step.UPDATE_MANIFEST_VERIFY, FlowDiagnostics.Result.SUCCEEDED);
            return result;
        } catch (Exception | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.UPDATE_MANIFEST_VERIFY, error);
            throw error;
        }
    }

    private Release verifyInternal(JsonObject envelope) throws Exception {
        String encoded = Json.string(envelope, "manifest"),
                signature = Json.string(envelope, "signature");
        if (encoded.length() > 22000 || !signature.matches("[A-Za-z0-9+/]{86}=="))
            throw new IOException("UPDATE_FORMAT");
        return verify(Base64.getDecoder().decode(encoded), signature);
    }

    public Release verify(byte[] bytes, String signature) throws Exception {
        trace.step(FlowDiagnostics.Step.UPDATE_MANIFEST_VERIFY, FlowDiagnostics.Result.STARTED);
        try {
            Release result = verifyInternal(bytes, signature);
            trace.step(
                    FlowDiagnostics.Step.UPDATE_MANIFEST_VERIFY, FlowDiagnostics.Result.SUCCEEDED);
            return result;
        } catch (Exception | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.UPDATE_MANIFEST_VERIFY, error);
            throw error;
        }
    }

    private Release verifyInternal(byte[] bytes, String signature) throws Exception {
        if (bytes.length > 16384 || !signature.matches("[A-Za-z0-9+/]{86}=="))
            throw new IOException("UPDATE_FORMAT");
        Ed25519Signer verifier = new Ed25519Signer();
        verifier.init(false, publicKey);
        verifier.update(bytes, 0, bytes.length);
        if (!verifier.verifySignature(Base64.getDecoder().decode(signature)))
            throw new IOException("UPDATE_SIGNATURE");
        JsonObject value = Json.object(new String(bytes, StandardCharsets.UTF_8), 16384);
        if (!"mintauth-release-v1".equals(Json.string(value, "schema"))
                || !Json.string(value, "commit").matches("[a-f0-9]{40}")
                || !Arrays.asList("pilot", "stable").contains(Json.string(value, "channel"))
                || !certificateHash.equals(Json.string(value, "jarSignerSha256")))
            throw new IOException("UPDATE_FORMAT");
        JsonArray entries = value.getAsJsonArray("files");
        if (entries == null || entries.size() != 3) throw new IOException("UPDATE_TARGETS");
        Map<String, Artifact> files = new HashMap<>();
        for (JsonElement element : entries) {
            JsonObject file = element.getAsJsonObject();
            String target = Json.string(file, "target"),
                    name = Json.string(file, "name"),
                    hash = Json.string(file, "sha256");
            String sizeText = file.get("size").getAsString();
            if (!Arrays.asList(TARGETS).contains(target)
                    || files.containsKey(target)
                    || name.length() > 160
                    || !name.startsWith("mintauth-" + target + "-")
                    || !name.matches("mintauth-[A-Za-z0-9._-]+\\.jar")
                    || !hash.matches("[a-f0-9]{64}")
                    || !sizeText.matches("[0-9]{1,8}")) throw new IOException("UPDATE_TARGETS");
            int size = Integer.parseInt(sizeText);
            if (size < 1 || size > MAX_JAR) throw new IOException("UPDATE_SIZE");
            files.put(target, new Artifact(target, name, hash, size));
        }
        return new Release(bytes, signature, value, files);
    }

    public void verifyJar(Path jar, String target, Artifact expected, String commit)
            throws Exception {
        trace.step(FlowDiagnostics.Step.UPDATE_JAR_VERIFY, FlowDiagnostics.Result.STARTED);
        try {
            verifyJarInternal(jar, target, expected, commit);
            trace.step(FlowDiagnostics.Step.UPDATE_JAR_VERIFY, FlowDiagnostics.Result.SUCCEEDED);
        } catch (Exception | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.UPDATE_JAR_VERIFY, error);
            throw error;
        }
    }

    private void verifyJarInternal(Path jar, String target, Artifact expected, String commit)
            throws Exception {
        if (!Arrays.asList(TARGETS).contains(target)
                || Files.isSymbolicLink(jar)
                || !Files.isRegularFile(jar, LinkOption.NOFOLLOW_LINKS)
                || Files.size(jar) < 1
                || Files.size(jar) > MAX_JAR) throw new IOException("UPDATE_JAR");
        if (expected != null
                && (Files.size(jar) != expected.size || !digest(jar).equals(expected.sha256)))
            throw new IOException("UPDATE_HASH");
        String adapter =
                "online/automint/mintauth/"
                        + (target.startsWith("forge")
                                ? "forge/MintAuthMod.class"
                                : "fabric/MintAuthClient.class");
        boolean hasAdapter = false, hasBuild = false;
        long total = 0;
        int count = 0;
        Set<String> names = new HashSet<>();
        try (JarFile archive = new JarFile(jar.toFile(), true)) {
            Enumeration<JarEntry> entries = archive.entries();
            byte[] buffer = new byte[8192];
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();
                if (++count > 30000 || !names.add(name))
                    throw new IOException("UPDATE_ARCHIVE_LIMIT");
                if (entry.isDirectory()) continue;
                ByteArrayOutputStream special =
                        name.equals(adapter) || name.equals("META-INF/mintauth/build.json")
                                ? new ByteArrayOutputStream()
                                : null;
                try (InputStream input = archive.getInputStream(entry)) {
                    int read;
                    while ((read = input.read(buffer)) != -1) {
                        total += read;
                        if (total > 128L * 1024 * 1024)
                            throw new IOException("UPDATE_ARCHIVE_LIMIT");
                        if (special != null) {
                            if (special.size() + read > 2 * 1024 * 1024)
                                throw new IOException("UPDATE_ARCHIVE_LIMIT");
                            special.write(buffer, 0, read);
                        }
                    }
                }
                boolean signatureFile =
                        name.matches("(?i)META-INF/(MANIFEST\\.MF|[A-Z0-9_-]+\\.(SF|RSA|DSA|EC))");
                if (!signatureFile) {
                    boolean trusted = false;
                    java.security.cert.Certificate[] certificates = entry.getCertificates();
                    if (certificates != null)
                        for (java.security.cert.Certificate certificate : certificates)
                            if (certificateHash.equals(
                                    hex(Crypto.sha256(certificate.getEncoded())))) trusted = true;
                    if (!trusted) throw new IOException("UPDATE_UNSIGNED_ENTRY");
                }
                if (name.equals(adapter)) {
                    byte[] data = special.toByteArray();
                    int major =
                            target.startsWith("forge")
                                    ? 52
                                    : target.equals("fabric-1.21.11") ? 65 : 69;
                    if (data.length < 8 || (data[6] & 255) * 256 + (data[7] & 255) != major)
                        throw new IOException("UPDATE_GAME_VERSION");
                    hasAdapter = true;
                }
                if (name.equals("META-INF/mintauth/build.json") && commit != null) {
                    JsonObject build =
                            Json.object(
                                    new String(special.toByteArray(), StandardCharsets.UTF_8),
                                    4096);
                    if (!commit.equals(Json.string(build, "commit")))
                        throw new IOException("UPDATE_SOURCE_BINDING");
                    hasBuild = true;
                }
            }
        }
        if (!hasAdapter || commit != null && !hasBuild)
            throw new IOException("UPDATE_GAME_VERSION");
    }

    static byte[] resource(String name) throws IOException {
        try (InputStream input =
                ReleaseVerifier.class.getResourceAsStream("/META-INF/mintauth/" + name)) {
            if (input == null) throw new IOException("UPDATE_RESOURCE");
            ByteArrayOutputStream result = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int n;
            while ((n = input.read(buffer)) != -1) {
                if (result.size() + n > 16384) throw new IOException("UPDATE_RESOURCE");
                result.write(buffer, 0, n);
            }
            return result.toByteArray();
        }
    }

    public static String digest(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
            byte[] buffer = new byte[65536];
            int n;
            long total = 0;
            while ((n = input.read(buffer)) != -1) {
                total += n;
                if (total > MAX_JAR) throw new IOException("UPDATE_SIZE");
                digest.update(buffer, 0, n);
            }
        }
        return hex(digest.digest());
    }

    static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) result.append(String.format(Locale.ROOT, "%02x", b & 255));
        return result.toString();
    }
}
