// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import com.google.gson.JsonObject;

import java.io.*;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;

public final class UpdateService {
    public interface Download {
        void get(String key, Path destination, int maximum) throws Exception;
    }

    private final Path game, installed, work, statePath;
    private final FlowDiagnostics trace;
    private final String target, commit;
    private final long buildTime;
    private final FileChannel runningChannel;
    private final FileLock runningLock;
    private volatile String message = "Automatic updates are ready.";
    private static final Set<String> STAGE_FILES =
            new HashSet<>(
                    Arrays.asList(
                            "candidate.jar",
                            "restore.jar",
                            "helper.jar",
                            "release.json",
                            "release.json.sig",
                            "request.json",
                            "result.json",
                            "helper.lock",
                            "helper.log",
                            "cancel"));

    public UpdateService(String target, Path gameRoot, Path installedJar) throws Exception {
        this(target, gameRoot, installedJar, FlowDiagnostics.silent());
    }

    UpdateService(String target, Path gameRoot, Path installedJar, FlowDiagnostics trace)
            throws Exception {
        this.trace = trace;
        trace.step(FlowDiagnostics.Step.UPDATE_SETUP, FlowDiagnostics.Result.STARTED);
        this.target = target;
        game = UpdateInstaller.safeDirectory(gameRoot);
        installed = UpdateInstaller.installed(game, installedJar);
        JsonObject build =
                Json.object(
                        new String(ReleaseVerifier.resource("build.json"), StandardCharsets.UTF_8),
                        4096);
        commit = Json.string(build, "commit");
        if (!commit.matches("[a-f0-9]{40}")
                || !build.get("committedAt").getAsString().matches("[0-9]{1,13}"))
            throw new IOException("UPDATE_BUILD");
        buildTime = build.get("committedAt").getAsLong() * 1000L;
        work = game.resolve(".mintauth-updates");
        if (!Files.exists(work, LinkOption.NOFOLLOW_LINKS)) Files.createDirectory(work);
        UpdateInstaller.safeDirectory(work);
        try {
            Files.setPosixFilePermissions(work, PosixFilePermissions.fromString("rwx------"));
        } catch (UnsupportedOperationException ignored) {
        }
        statePath = work.resolve("state.json");
        runningChannel =
                FileChannel.open(
                        work.resolve("running.lock"),
                        StandardOpenOption.CREATE,
                        StandardOpenOption.READ,
                        StandardOpenOption.WRITE,
                        LinkOption.NOFOLLOW_LINKS);
        FileLock lease;
        try {
            lease = runningChannel.tryLock(0L, Long.MAX_VALUE, true);
        } catch (Exception error) {
            runningChannel.close();
            throw error;
        }
        if (lease == null) {
            runningChannel.close();
            throw new IOException("UPDATE_APPLY_IN_PROGRESS");
        }
        runningLock = lease;
        Runtime.getRuntime()
                .addShutdownHook(
                        new Thread(
                                () -> {
                                    try {
                                        runningLock.release();
                                    } catch (Exception ignored) {
                                    }
                                    try {
                                        runningChannel.close();
                                    } catch (Exception ignored) {
                                    }
                                },
                                "MintAuth update lease"));
    }

    public String message() {
        return message;
    }

    private JsonObject state() throws IOException {
        return Files.exists(statePath, LinkOption.NOFOLLOW_LINKS)
                ? UpdateInstaller.read(statePath, 4096)
                : new JsonObject();
    }

    private void save(JsonObject value) throws IOException {
        UpdateInstaller.atomic(statePath, Json.GSON.toJson(value).getBytes(StandardCharsets.UTF_8));
    }

    private Path stage(String id) throws IOException {
        if (!id.matches("[a-f0-9]{32}")) throw new IOException("UPDATE_STAGE");
        return UpdateInstaller.safeDirectory(work.resolve(id));
    }

    public synchronized void resume() {
        trace.step(FlowDiagnostics.Step.UPDATE_RESUME, FlowDiagnostics.Result.STARTED);
        try {
            JsonObject value = state();
            String pending = Json.optional(value, "pending");
            if (pending == null) {
                trace.step(FlowDiagnostics.Step.UPDATE_RESUME, FlowDiagnostics.Result.EMPTY);
                cleanup();
                return;
            }
            Path stage = stage(pending);
            if (Files.exists(stage.resolve("result.json"), LinkOption.NOFOLLOW_LINKS)
                    || Files.exists(stage.resolve("cancel"), LinkOption.NOFOLLOW_LINKS)) {
                boolean success =
                        Files.exists(stage.resolve("result.json"), LinkOption.NOFOLLOW_LINKS)
                                && "complete"
                                        .equals(
                                                Json.string(
                                                        UpdateInstaller.read(
                                                                stage.resolve("result.json"), 1024),
                                                        "status"));
                value.remove("pending");
                save(value);
                message =
                        success
                                ? "MintAuth was updated successfully."
                                : "The previous update did not apply. Check again to retry.";
                cleanup();
                trace.step(
                        FlowDiagnostics.Step.UPDATE_RESUME,
                        success ? FlowDiagnostics.Result.SUCCEEDED : FlowDiagnostics.Result.FAILED);
                return;
            }
            ReleaseVerifier verifier = new ReleaseVerifier().withDiagnostics(trace);
            ReleaseVerifier.Release release = stagedRelease(verifier, stage);
            if (ReleaseVerifier.digest(installed).equals(release.artifact(target).sha256)) {
                verifier.verifyJar(installed, target, release.artifact(target), release.commit);
                UpdateInstaller.atomic(
                        stage.resolve("result.json"),
                        "{\"status\":\"complete\"}".getBytes(StandardCharsets.UTF_8));
                value.remove("pending");
                save(value);
                cleanup();
                message = "MintAuth was updated successfully.";
                trace.step(FlowDiagnostics.Step.UPDATE_RESUME, FlowDiagnostics.Result.SUCCEEDED);
                return;
            }
            verifier.verifyJar(
                    stage.resolve("candidate.jar"),
                    target,
                    release.artifact(target),
                    release.commit);
            verifier.verifyJar(installed, target, null, null);
            startHelper(stage);
            message = "Update ready. It installs after Minecraft closes.";
        } catch (Exception | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.UPDATE_RESUME, error);
            message = "An update could not be resumed. Your installed JAR is unchanged.";
        }
    }

    public synchronized void cancel() {
        trace.step(FlowDiagnostics.Step.UPDATE_CANCEL, FlowDiagnostics.Result.STARTED);
        try {
            JsonObject value = state();
            String pending = Json.optional(value, "pending");
            if (pending != null) {
                Path folder = stage(pending);
                if (!Files.exists(folder.resolve("cancel"), LinkOption.NOFOLLOW_LINKS))
                    Files.write(
                            folder.resolve("cancel"), new byte[0], StandardOpenOption.CREATE_NEW);
                value.remove("pending");
                save(value);
            }
            message = "Automatic updates are off.";
            trace.step(FlowDiagnostics.Step.UPDATE_CANCEL, FlowDiagnostics.Result.CANCELLED);
        } catch (Exception error) {
            trace.failure(FlowDiagnostics.Step.UPDATE_CANCEL, error);
            message =
                    "Automatic updates are off; a previously staged update could not be cancelled.";
        }
    }

    public synchronized void check(JsonObject metadata, Download download)
            throws ProtocolClient.ApiException {
        Path attempt = null;
        trace.step(FlowDiagnostics.Step.UPDATE_CHECK, FlowDiagnostics.Result.STARTED);
        try {
            JsonObject state = state();
            if (Json.optional(state, "pending") != null) {
                message = "Update ready. It installs after Minecraft closes.";
                trace.step(FlowDiagnostics.Step.UPDATE_CHECK, FlowDiagnostics.Result.EXISTING);
                return;
            }
            ReleaseVerifier verifier = new ReleaseVerifier().withDiagnostics(trace);
            ReleaseVerifier.Release release = verifier.verify(metadata);
            if (commit.equals(release.commit)) {
                message = "MintAuth is up to date.";
                trace.step(FlowDiagnostics.Step.UPDATE_CHECK, FlowDiagnostics.Result.EXISTING);
                return;
            }
            if (olderThanFloor(
                    release.createdAt,
                    buildTime,
                    state.has("acceptedAt") ? state.get("acceptedAt").getAsLong() : 0L)) {
                message = "An older signed release was ignored.";
                trace.step(FlowDiagnostics.Step.UPDATE_CHECK, FlowDiagnostics.Result.BLOCKED);
                return;
            }
            verifier.verifyJar(installed, target, null, null);
            ReleaseVerifier.Artifact artifact = release.artifact(target);
            String id = UUID.randomUUID().toString().replace("-", "");
            Path stage = work.resolve(id);
            trace.step(FlowDiagnostics.Step.UPDATE_STAGE, FlowDiagnostics.Result.STARTED);
            Files.createDirectory(stage);
            attempt = stage;
            try {
                Files.setPosixFilePermissions(stage, PosixFilePermissions.fromString("rwx------"));
            } catch (UnsupportedOperationException ignored) {
            }
            message = "Downloading a signed MintAuth update...";
            String key =
                    target.equals("forge-1.8.9")
                            ? "forge189"
                            : target.equals("fabric-1.21.11") ? "fabric121" : "fabric263";
            Path candidate = stage.resolve("candidate.jar");
            download.get(key, candidate, artifact.size);
            try (FileChannel durable = FileChannel.open(candidate, StandardOpenOption.WRITE)) {
                durable.force(true);
            }
            verifier.verifyJar(candidate, target, artifact, release.commit);
            Files.write(
                    stage.resolve("release.json"), release.bytes, StandardOpenOption.CREATE_NEW);
            Files.write(
                    stage.resolve("release.json.sig"),
                    release.signature.getBytes(StandardCharsets.US_ASCII),
                    StandardOpenOption.CREATE_NEW);
            Files.copy(installed, stage.resolve("helper.jar"));
            verifier.verifyJar(stage.resolve("helper.jar"), target, null, null);
            JsonObject request = Json.obj("gameRoot", game.toString());
            request.addProperty("installedJar", installed.toString());
            request.addProperty("oldSha256", ReleaseVerifier.digest(installed));
            request.addProperty("target", target);
            Files.write(
                    stage.resolve("request.json"),
                    Json.GSON.toJson(request).getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE_NEW);
            state.addProperty("pending", id);
            state.addProperty("acceptedAt", release.createdAt);
            save(state);
            trace.step(FlowDiagnostics.Step.UPDATE_STAGE, FlowDiagnostics.Result.SUCCEEDED);
            startHelper(stage);
            message = "Update ready. It installs after Minecraft closes.";
        } catch (Exception | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.UPDATE_CHECK, error);
            if (attempt != null)
                try {
                    UpdateInstaller.atomic(
                            attempt.resolve("result.json"),
                            "{\"status\":\"failed\"}".getBytes(StandardCharsets.UTF_8));
                } catch (Exception ignored) {
                }
            message = "Update check failed. Minecraft can continue; retry later.";
            if (error instanceof ProtocolClient.ApiException
                    && ((ProtocolClient.ApiException) error).grantLost())
                throw (ProtocolClient.ApiException) error;
        }
    }

    static boolean olderThanFloor(long releaseTime, long buildTime, long acceptedTime) {
        return releaseTime < Math.max(buildTime, acceptedTime);
    }

    private ReleaseVerifier.Release stagedRelease(ReleaseVerifier verifier, Path stage)
            throws Exception {
        Path manifest = stage.resolve("release.json"),
                signature = stage.resolve("release.json.sig");
        if (Files.isSymbolicLink(manifest)
                || Files.isSymbolicLink(signature)
                || Files.size(manifest) > 16384
                || Files.size(signature) > 256) throw new IOException("UPDATE_METADATA");
        return verifier.verify(
                Files.readAllBytes(manifest),
                new String(Files.readAllBytes(signature), StandardCharsets.US_ASCII).trim());
    }

    private void startHelper(Path stage) throws IOException {
        trace.step(FlowDiagnostics.Step.UPDATE_HELPER, FlowDiagnostics.Result.STARTED);
        try {
            startHelperInternal(stage);
            trace.step(FlowDiagnostics.Step.UPDATE_HELPER, FlowDiagnostics.Result.SUCCEEDED);
        } catch (IOException | RuntimeException | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.UPDATE_HELPER, error);
            throw error;
        }
    }

    private void startHelperInternal(Path stage) throws IOException {
        String executable =
                System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win")
                        ? "javaw.exe"
                        : "java";
        Path java = Paths.get(System.getProperty("java.home"), "bin", executable);
        if (!Files.isRegularFile(java)) throw new IOException("UPDATE_JAVA");
        new ProcessBuilder(
                        java.toString(),
                        "-Xmx96m",
                        "-XX:-UsePerfData",
                        "-cp",
                        stage.resolve("helper.jar").toString(),
                        UpdateInstaller.class.getName(),
                        stage.resolve("request.json").toString())
                .redirectErrorStream(true)
                .redirectOutput(stage.resolve("helper.log").toFile())
                .start();
    }

    private void cleanup() {
        try (DirectoryStream<Path> entries = Files.newDirectoryStream(work)) {
            for (Path folder : entries) {
                if (!folder.getFileName().toString().matches("[a-f0-9]{32}")
                        || Files.isSymbolicLink(folder)
                        || !Files.isDirectory(folder)) continue;
                if (!Files.exists(folder.resolve("result.json"), LinkOption.NOFOLLOW_LINKS)
                        && !Files.exists(folder.resolve("cancel"), LinkOption.NOFOLLOW_LINKS))
                    continue;
                boolean complete = true;
                try (DirectoryStream<Path> files = Files.newDirectoryStream(folder)) {
                    for (Path file : files) {
                        String name = file.getFileName().toString();
                        if (name.equals("result.json") || name.equals("cancel")) continue;
                        if (!STAGE_FILES.contains(name)
                                || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
                            complete = false;
                            continue;
                        }
                        try {
                            Files.delete(file);
                        } catch (IOException ignored) {
                            complete = false;
                        }
                    }
                } catch (IOException ignored) {
                    complete = false;
                }
                if (complete)
                    try {
                        Files.deleteIfExists(folder.resolve("result.json"));
                        Files.deleteIfExists(folder.resolve("cancel"));
                        Files.delete(folder);
                    } catch (IOException ignored) {
                    }
            }
        } catch (IOException error) {
            trace.failure(FlowDiagnostics.Step.UPDATE_CLEANUP, error);
        }
        Path backups = work.resolve("backups");
        if (!Files.isDirectory(backups, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(backups))
            return;
        try (DirectoryStream<Path> entries = Files.newDirectoryStream(backups)) {
            List<Path> files = new ArrayList<>();
            for (Path file : entries)
                if (file.getFileName().toString().matches("[a-f0-9]{64}\\.jar\\.backup")
                        && Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) files.add(file);
            files.sort(
                    (a, b) -> {
                        try {
                            return Files.getLastModifiedTime(b)
                                    .compareTo(Files.getLastModifiedTime(a));
                        } catch (IOException e) {
                            return 0;
                        }
                    });
            for (int i = 2; i < files.size(); i++) Files.delete(files.get(i));
        } catch (IOException error) {
            trace.failure(FlowDiagnostics.Step.UPDATE_CLEANUP, error);
        }
    }
}
