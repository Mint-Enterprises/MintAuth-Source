// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import static org.junit.Assert.*;

import com.google.gson.*;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.junit.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.jar.*;

public class UpdateVerificationTest {
    private static Path root, oldJar, newJar;
    private static Ed25519PrivateKeyParameters signing;
    private static ReleaseVerifier verifier;
    private static final String OLD = repeat('a', 40), NEXT = repeat('b', 40);
    private static byte[] certificate;

    private static String repeat(char c, int count) {
        char[] value = new char[count];
        Arrays.fill(value, c);
        return new String(value);
    }

    private static String tool(String name) {
        String suffix =
                System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win")
                        ? ".exe"
                        : "";
        Path home = Paths.get(System.getProperty("java.home"));
        Path binary = home.resolve("bin").resolve(name + suffix);
        if (!Files.exists(binary)) binary = home.getParent().resolve("bin").resolve(name + suffix);
        return binary.toString();
    }

    private static void command(String... args) throws Exception {
        Path log = root.resolve("test-command.log");
        Process process =
                new ProcessBuilder(args)
                        .redirectErrorStream(true)
                        .redirectOutput(log.toFile())
                        .start();
        if (!process.waitFor(60, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            fail("Synthetic signing command timed out");
        }
        assertEquals("Synthetic signing command failed", 0, process.exitValue());
    }

    private static byte[] publicPem(Ed25519PrivateKeyParameters key) throws Exception {
        byte[] spki =
                SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key.generatePublicKey())
                        .getEncoded();
        return ("-----BEGIN PUBLIC KEY-----\n"
                        + Base64.getEncoder().encodeToString(spki)
                        + "\n-----END PUBLIC KEY-----\n")
                .getBytes(StandardCharsets.US_ASCII);
    }

    @BeforeClass
    public static void setup() throws Exception {
        root = Files.createTempDirectory("mintauth-update-test-");
        signing = new Ed25519PrivateKeyParameters(new SecureRandom());
        Path keystore = root.resolve("synthetic.p12"), cert = root.resolve("synthetic.crt");
        command(
                tool("keytool"),
                "-genkeypair",
                "-alias",
                "test",
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
                "-sigalg",
                "SHA256withRSA",
                "-dname",
                "CN=Synthetic MintAuth Test",
                "-validity",
                "30",
                "-keystore",
                keystore.toString(),
                "-storetype",
                "PKCS12",
                "-storepass",
                "test-only-password",
                "-keypass",
                "test-only-password",
                "-noprompt");
        command(
                tool("keytool"),
                "-exportcert",
                "-alias",
                "test",
                "-keystore",
                keystore.toString(),
                "-storepass",
                "test-only-password",
                "-file",
                cert.toString());
        certificate = Files.readAllBytes(cert);
        verifier = new ReleaseVerifier(publicPem(signing), certificate);
        oldJar = fixture("old.jar", OLD);
        newJar = fixture("new.jar", NEXT);
        for (Path file : Arrays.asList(oldJar, newJar))
            command(
                    tool("jarsigner"),
                    "-keystore",
                    keystore.toString(),
                    "-storepass",
                    "test-only-password",
                    "-sigalg",
                    "SHA256withRSA",
                    "-digestalg",
                    "SHA-256",
                    file.toString(),
                    "test");
    }

    private static Path fixture(String name, String commit) throws Exception {
        Path jar = root.resolve(name);
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar), manifest)) {
            output.putNextEntry(new JarEntry("online/automint/mintauth/forge/MintAuthMod.class"));
            output.write(
                    new byte[] {(byte) 0xca, (byte) 0xfe, (byte) 0xba, (byte) 0xbe, 0, 0, 0, 52});
            output.closeEntry();
            output.putNextEntry(new JarEntry("META-INF/mintauth/build.json"));
            output.write(
                    ("{\"commit\":\"" + commit + "\",\"committedAt\":1}")
                            .getBytes(StandardCharsets.UTF_8));
            output.closeEntry();
        }
        return jar;
    }

    private static JsonObject manifest() throws Exception {
        JsonObject value = Json.obj("schema", "mintauth-release-v1");
        value.addProperty("commit", NEXT);
        value.addProperty("channel", "pilot");
        value.addProperty("createdAt", "2026-10-28T00:00:00.000Z");
        value.addProperty("jarSignerSha256", ReleaseVerifier.hex(Crypto.sha256(certificate)));
        JsonArray files = new JsonArray();
        for (String target : Arrays.asList("forge-1.8.9", "fabric-1.21.11", "fabric-26.3")) {
            JsonObject file = Json.obj("target", target);
            file.addProperty("name", "mintauth-" + target + "-test.jar");
            file.addProperty("size", Files.size(newJar));
            file.addProperty("sha256", ReleaseVerifier.digest(newJar));
            files.add(file);
        }
        value.add("files", files);
        return value;
    }

    private static ReleaseVerifier.Release release(JsonObject value) throws Exception {
        byte[] bytes = Json.GSON.toJson(value).getBytes(StandardCharsets.UTF_8);
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, signing);
        signer.update(bytes, 0, bytes.length);
        return verifier.verify(
                bytes, Base64.getEncoder().encodeToString(signer.generateSignature()));
    }

    @Test
    public void verifiesSignedMetadataJarAndSourceBinding() throws Exception {
        ReleaseVerifier.Release release = release(manifest());
        verifier.verifyJar(newJar, "forge-1.8.9", release.artifact("forge-1.8.9"), NEXT);
        assertEquals(NEXT, release.commit);
        try {
            verifier.verifyJar(newJar, "forge-1.8.9", release.artifact("forge-1.8.9"), OLD);
            fail();
        } catch (IOException expected) {
        }
        try {
            verifier.verifyJar(newJar, "fabric-1.21.11", release.artifact("fabric-1.21.11"), NEXT);
            fail();
        } catch (IOException expected) {
        }
    }

    @Test
    public void rejectsTamperedMetadataWrongKeysAndSignedTraversal() throws Exception {
        ReleaseVerifier.Release release = release(manifest());
        byte[] bytes = release.bytes.clone();
        bytes[bytes.length - 1] = ' ';
        try {
            verifier.verify(bytes, release.signature);
            fail();
        } catch (IOException expected) {
        }
        ReleaseVerifier other =
                new ReleaseVerifier(
                        publicPem(new Ed25519PrivateKeyParameters(new SecureRandom())),
                        certificate);
        try {
            other.verify(release.bytes, release.signature);
            fail();
        } catch (IOException expected) {
        }
        JsonObject traversal = manifest();
        traversal
                .getAsJsonArray("files")
                .get(0)
                .getAsJsonObject()
                .addProperty("name", "../../other.jar");
        try {
            release(traversal);
            fail();
        } catch (IOException expected) {
        }
    }

    @Test
    public void rejectsUnsignedEntriesAddedToAnOtherwiseSignedJar() throws Exception {
        Path changed = root.resolve("unsigned-addition.jar");
        try (JarFile input = new JarFile(newJar.toFile());
                JarOutputStream output = new JarOutputStream(Files.newOutputStream(changed))) {
            Enumeration<JarEntry> entries = input.entries();
            byte[] buffer = new byte[8192];
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                output.putNextEntry(new JarEntry(entry.getName()));
                try (InputStream stream = input.getInputStream(entry)) {
                    int n;
                    while ((n = stream.read(buffer)) != -1) output.write(buffer, 0, n);
                }
                output.closeEntry();
            }
            output.putNextEntry(new JarEntry("META-INF/services/unsigned-provider"));
            output.write(1);
            output.closeEntry();
        }
        try {
            verifier.verifyJar(changed, "forge-1.8.9", null, null);
            fail();
        } catch (IOException expected) {
            assertEquals("UPDATE_UNSIGNED_ENTRY", expected.getMessage());
        }
    }

    @Test
    public void atomicallyInstallsMatchingUpdateAndKeepsVerifiedBackup() throws Exception {
        Path game = Files.createDirectory(root.resolve("game-good")),
                mods = Files.createDirectory(game.resolve("mods"));
        Files.createDirectory(game.resolve(".mintauth-updates"));
        Path installed = Files.copy(oldJar, mods.resolve("mintauth.jar")),
                candidate = Files.copy(newJar, game.resolve("candidate.jar"));
        String oldHash = ReleaseVerifier.digest(installed);
        ReleaseVerifier.Release release = release(manifest());
        UpdateInstaller.apply(
                verifier,
                installed,
                game,
                candidate,
                "forge-1.8.9",
                oldHash,
                release.artifact("forge-1.8.9"),
                NEXT);
        assertEquals(ReleaseVerifier.digest(newJar), ReleaseVerifier.digest(installed));
        assertEquals(
                oldHash,
                ReleaseVerifier.digest(
                        game.resolve(".mintauth-updates/backups/" + oldHash + ".jar.backup")));
    }

    @Test
    public void changedInstallationCannotBeOverwrittenByLateUpdater() throws Exception {
        Path game = Files.createDirectory(root.resolve("game-changed")),
                mods = Files.createDirectory(game.resolve("mods"));
        Files.createDirectory(game.resolve(".mintauth-updates"));
        Path installed = Files.copy(oldJar, mods.resolve("mintauth.jar")),
                candidate = Files.copy(newJar, game.resolve("candidate.jar"));
        String before = ReleaseVerifier.digest(installed);
        ReleaseVerifier.Release release = release(manifest());
        try {
            UpdateInstaller.apply(
                    verifier,
                    installed,
                    game,
                    candidate,
                    "forge-1.8.9",
                    repeat('c', 64),
                    release.artifact("forge-1.8.9"),
                    NEXT);
            fail();
        } catch (IOException expected) {
        }
        assertEquals(before, ReleaseVerifier.digest(installed));
    }

    @Test
    public void rejectsRollbackAgainstBuildAndAcceptedReleaseTimes() {
        assertTrue(UpdateService.olderThanFloor(99, 100, 50));
        assertTrue(UpdateService.olderThanFloor(149, 100, 150));
        assertFalse(UpdateService.olderThanFloor(150, 100, 150));
        assertFalse(UpdateService.olderThanFloor(151, 100, 150));
    }

    @Test
    public void diagnosticsOnlyCallsTheVerifiedPinnedJarValid() throws Exception {
        List<String> lines = new ArrayList<>();
        StartupDiagnostics log = new StartupDiagnostics(lines::add);
        log.jar(newJar, "forge-1.8.9", NEXT, verifier);
        assertTrue(lines.get(0).contains("signature=VERIFIED_PINNED_CERTIFICATE"));
        assertTrue(lines.get(0).contains(ReleaseVerifier.digest(newJar)));
        Path unsigned = fixture("diagnostic-unsigned.jar", NEXT);
        log.jar(unsigned, "forge-1.8.9", NEXT, verifier);
        assertTrue(lines.get(1).contains("signature=UNVERIFIED_OR_UNAVAILABLE"));
        log.jar(newJar, "forge-1.8.9", OLD, verifier);
        assertTrue(lines.get(2).contains("signature=UNVERIFIED_OR_UNAVAILABLE"));
    }

    @Test
    public void releaseKeysMustBeExactEd25519SpkiWithoutParameters() throws Exception {
        org.bouncycastle.asn1.ASN1ObjectIdentifier ed =
                org.bouncycastle.internal.asn1.edec.EdECObjectIdentifiers.id_Ed25519;
        org.bouncycastle.asn1.x509.SubjectPublicKeyInfo padded =
                org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(
                        new org.bouncycastle.asn1.DERSequence(new org.bouncycastle.asn1.ASN1Encodable[] {
                            new org.bouncycastle.asn1.x509.AlgorithmIdentifier(ed),
                            new org.bouncycastle.asn1.DERBitString(new byte[32], 1)
                        }));
        for (org.bouncycastle.asn1.x509.SubjectPublicKeyInfo invalid : Arrays.asList(padded,
                new org.bouncycastle.asn1.x509.SubjectPublicKeyInfo(
                        new org.bouncycastle.asn1.x509.AlgorithmIdentifier(ed,
                                org.bouncycastle.asn1.DERNull.INSTANCE), new byte[32]),
                new org.bouncycastle.asn1.x509.SubjectPublicKeyInfo(
                        new org.bouncycastle.asn1.x509.AlgorithmIdentifier(ed), new byte[31]),
                new org.bouncycastle.asn1.x509.SubjectPublicKeyInfo(
                        new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                                org.bouncycastle.internal.asn1.edec.EdECObjectIdentifiers.id_X25519),
                        new byte[32]))) {
            byte[] pem = ("-----BEGIN PUBLIC KEY-----\n"
                    + Base64.getEncoder().encodeToString(invalid.getEncoded())
                    + "\n-----END PUBLIC KEY-----\n").getBytes(StandardCharsets.US_ASCII);
            try {
                new ReleaseVerifier(pem, certificate);
                fail("Only the exact Ed25519 release-key format is allowed");
            } catch (IOException expected) {
                assertEquals("UPDATE_KEY", expected.getMessage());
            }
        }
    }

    @AfterClass
    public static void cleanup() throws Exception {
        if (root == null
                || !root.getParent()
                        .equals(
                                Paths.get(System.getProperty("java.io.tmpdir"))
                                        .toAbsolutePath()
                                        .normalize())
                || !root.getFileName().toString().startsWith("mintauth-update-test-"))
            throw new IOException("Unsafe test cleanup");
        try (java.util.stream.Stream<Path> files = Files.walk(root)) {
            for (Path file : (Iterable<Path>) files.sorted(Comparator.reverseOrder())::iterator)
                Files.delete(file);
        }
    }
}
