// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import com.google.gson.JsonObject;

import java.io.*;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.concurrent.TimeUnit;

public final class UpdateInstaller {
    private UpdateInstaller() {}

    private static final FlowDiagnostics trace =
            new FlowDiagnostics(line -> System.out.println(line), line -> System.err.println(line));

    static Path safeDirectory(Path path) throws IOException {
        Path absolute = path.toAbsolutePath().normalize();
        for (Path part = absolute; part != null; part = part.getParent())
            if (Files.isSymbolicLink(part)) throw new IOException("UPDATE_SYMLINK");
        if (!Files.isDirectory(absolute, LinkOption.NOFOLLOW_LINKS))
            throw new IOException("UPDATE_DIRECTORY");
        return absolute.toRealPath();
    }

    static JsonObject read(Path file, int maximum) throws IOException {
        if (Files.isSymbolicLink(file)
                || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)
                || Files.size(file) > maximum) throw new IOException("UPDATE_FILE");
        return Json.object(new String(Files.readAllBytes(file), StandardCharsets.UTF_8), maximum);
    }

    static void atomic(Path destination, byte[] bytes) throws IOException {
        if (Files.isSymbolicLink(destination)) throw new IOException("UPDATE_SYMLINK");
        Path temporary =
                destination.resolveSibling(
                        destination.getFileName() + "." + java.util.UUID.randomUUID() + ".tmp");
        Files.write(temporary, bytes, StandardOpenOption.CREATE_NEW);
        try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
            channel.force(true);
        }
        Files.move(
                temporary,
                destination,
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING);
    }

    static Path installed(Path gameRoot, Path jar) throws IOException {
        Path game = safeDirectory(gameRoot), mods = safeDirectory(game.resolve("mods"));
        Path file = jar.toAbsolutePath().normalize();
        if (Files.isSymbolicLink(file)
                || !safeDirectory(file.getParent()).startsWith(mods)
                || !file.getFileName().toString().endsWith(".jar"))
            throw new IOException("UPDATE_INSTALL_PATH");
        return file;
    }

    public static void main(String[] args) {
        trace.step(FlowDiagnostics.Step.UPDATE_HELPER, FlowDiagnostics.Result.STARTED);
        Path stage = null;
        try {
            if (args.length != 1) throw new IOException("UPDATE_ARGUMENTS");
            Path request = Paths.get(args[0]).toAbsolutePath().normalize();
            Path folder = safeDirectory(request.getParent());
            if (!folder.getFileName().toString().matches("[a-f0-9]{32}")
                    || !request.getFileName().toString().equals("request.json"))
                throw new IOException("UPDATE_REQUEST");
            JsonObject recipe = read(request, 8192);
            Path game = safeDirectory(Paths.get(Json.string(recipe, "gameRoot")));
            Path work = safeDirectory(game.resolve(".mintauth-updates"));
            if (!folder.getParent().equals(work)) throw new IOException("UPDATE_REQUEST");
            stage = folder;
            Path target = installed(game, Paths.get(Json.string(recipe, "installedJar")));
            String oldHash = Json.string(recipe, "oldSha256"),
                    targetId = Json.string(recipe, "target");
            if (!oldHash.matches("[a-f0-9]{64}")) throw new IOException("UPDATE_REQUEST");
            ReleaseVerifier verifier = new ReleaseVerifier().withDiagnostics(trace);
            Path candidate = stage.resolve("candidate.jar");
            Path manifestPath = stage.resolve("release.json");
            if (Files.isSymbolicLink(manifestPath) || Files.size(manifestPath) > 16384)
                throw new IOException("UPDATE_METADATA");
            byte[] bytes = Files.readAllBytes(manifestPath);
            Path signaturePath = stage.resolve("release.json.sig");
            if (Files.isSymbolicLink(signaturePath) || Files.size(signaturePath) > 256)
                throw new IOException("UPDATE_METADATA");
            ReleaseVerifier.Release release =
                    verifier.verify(
                            bytes,
                            new String(Files.readAllBytes(signaturePath), StandardCharsets.US_ASCII)
                                    .trim());
            ReleaseVerifier.Artifact file = release.artifact(targetId);
            verifier.verifyJar(candidate, targetId, file, release.commit);
            try (FileChannel leader =
                            FileChannel.open(
                                    stage.resolve("helper.lock"),
                                    StandardOpenOption.CREATE,
                                    StandardOpenOption.WRITE,
                                    LinkOption.NOFOLLOW_LINKS);
                    FileLock leaderLock = leader.tryLock()) {
                if (leaderLock == null) {
                    trace.step(FlowDiagnostics.Step.UPDATE_HELPER, FlowDiagnostics.Result.SKIPPED);
                    return;
                }
                try (FileChannel running =
                        FileChannel.open(
                                work.resolve("running.lock"),
                                StandardOpenOption.CREATE,
                                StandardOpenOption.READ,
                                StandardOpenOption.WRITE,
                                LinkOption.NOFOLLOW_LINKS)) {
                    trace.step(FlowDiagnostics.Step.UPDATE_WAIT, FlowDiagnostics.Result.STARTED);
                    long deadline = System.nanoTime() + TimeUnit.HOURS.toNanos(24);
                    while (System.nanoTime() < deadline
                            && !Files.exists(stage.resolve("cancel"), LinkOption.NOFOLLOW_LINKS)) {
                        try (FileLock exclusive = running.tryLock()) {
                            if (exclusive != null) {
                                apply(
                                        verifier,
                                        target,
                                        game,
                                        candidate,
                                        targetId,
                                        oldHash,
                                        file,
                                        release.commit);
                                atomic(
                                        stage.resolve("result.json"),
                                        "{\"status\":\"complete\"}"
                                                .getBytes(StandardCharsets.UTF_8));
                                trace.step(
                                        FlowDiagnostics.Step.UPDATE_HELPER,
                                        FlowDiagnostics.Result.SUCCEEDED);
                                return;
                            }
                        } catch (OverlappingFileLockException ignored) {
                        }
                        Thread.sleep(500);
                    }
                    trace.step(FlowDiagnostics.Step.UPDATE_WAIT, FlowDiagnostics.Result.CANCELLED);
                }
            }
        } catch (Exception | LinkageError failure) {
            trace.failure(FlowDiagnostics.Step.UPDATE_HELPER, failure);
            System.err.println(
                    "MintAuth update was not installed; check Updates or reinstall from the"
                            + " official downloads page.");
            if (stage != null)
                try {
                    atomic(
                            stage.resolve("result.json"),
                            "{\"status\":\"failed\"}".getBytes(StandardCharsets.UTF_8));
                } catch (Exception ignored) {
                }
        }
    }

    static void apply(
            ReleaseVerifier verifier,
            Path target,
            Path game,
            Path candidate,
            String targetId,
            String oldHash,
            ReleaseVerifier.Artifact file,
            String commit)
            throws Exception {
        trace.step(FlowDiagnostics.Step.UPDATE_APPLY, FlowDiagnostics.Result.STARTED);
        try {
            applyInternal(verifier, target, game, candidate, targetId, oldHash, file, commit);
            trace.step(FlowDiagnostics.Step.UPDATE_APPLY, FlowDiagnostics.Result.SUCCEEDED);
        } catch (Exception | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.UPDATE_APPLY, error);
            throw error;
        }
    }

    static void applyInternal(
            ReleaseVerifier verifier,
            Path target,
            Path game,
            Path candidate,
            String targetId,
            String oldHash,
            ReleaseVerifier.Artifact file,
            String commit)
            throws Exception {
        if (ReleaseVerifier.digest(target).equals(file.sha256))
            return;
        if (!ReleaseVerifier.digest(target).equals(oldHash))
            throw new IOException("UPDATE_INSTALL_CHANGED");
        verifier.verifyJar(target, targetId, null, null);
        verifier.verifyJar(candidate, targetId, file, commit);
        trace.step(FlowDiagnostics.Step.UPDATE_BACKUP, FlowDiagnostics.Result.STARTED);
        Path backups = game.resolve(".mintauth-updates").resolve("backups");
        if (!Files.exists(backups, LinkOption.NOFOLLOW_LINKS)) Files.createDirectory(backups);
        safeDirectory(backups);
        Path backup = backups.resolve(oldHash + ".jar.backup");
        if (!Files.exists(backup, LinkOption.NOFOLLOW_LINKS)) Files.copy(target, backup);
        if (!ReleaseVerifier.digest(backup).equals(oldHash)) throw new IOException("UPDATE_BACKUP");
        try (FileChannel durable = FileChannel.open(backup, StandardOpenOption.WRITE)) {
            durable.force(true);
        }
        trace.step(FlowDiagnostics.Step.UPDATE_BACKUP, FlowDiagnostics.Result.SUCCEEDED);
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
        while (true) {
            DosFileAttributeView dos =
                    Files.getFileAttributeView(
                            target, DosFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            boolean readOnly = dos != null && dos.readAttributes().isReadOnly();
            try {
                if (readOnly) dos.setReadOnly(false);
                Files.move(
                        candidate,
                        target,
                        StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
                break;
            } catch (AccessDeniedException locked) {
                trace.state(FlowDiagnostics.Step.UPDATE_APPLY, FlowDiagnostics.Result.RETRYING);
                if (readOnly) dos.setReadOnly(true);
                if (System.nanoTime() >= deadline) throw locked;
                Thread.sleep(250);
            } catch (Exception error) {
                if (readOnly) dos.setReadOnly(true);
                throw error;
            }
        }
        try {
            verifier.verifyJar(target, targetId, file, commit);
        } catch (Exception failure) {
            trace.failure(FlowDiagnostics.Step.UPDATE_JAR_VERIFY, failure);
            trace.step(FlowDiagnostics.Step.UPDATE_ROLLBACK, FlowDiagnostics.Result.STARTED);
            Path restore = candidate.resolveSibling("restore.jar");
            Files.copy(backup, restore);
            if (!ReleaseVerifier.digest(restore).equals(oldHash)) throw failure;
            Files.move(
                    restore,
                    target,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
            trace.step(FlowDiagnostics.Step.UPDATE_ROLLBACK, FlowDiagnostics.Result.SUCCEEDED);
            throw failure;
        }
    }
}
