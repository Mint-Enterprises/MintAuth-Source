// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import com.google.gson.JsonObject;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.UUID;

public final class InstanceRegistry {
    private final Path root;
    private volatile FlowDiagnostics trace = FlowDiagnostics.silent();

    void setDiagnostics(FlowDiagnostics value) {
        trace = value;
    }

    private final String instance = UUID.randomUUID().toString();

    public InstanceRegistry(Path root) {
        this.root = root;
    }

    private Path file(String generation) {
        return root.resolve("instance-" + UUID.fromString(generation) + "-" + instance + ".json");
    }

    public synchronized void report(String generation, boolean cleared) throws Exception {
        trace.step(FlowDiagnostics.Step.INSTANCE_REPORT, FlowDiagnostics.Result.STARTED);
        try {
            reportInternal(generation, cleared);
            trace.step(FlowDiagnostics.Step.INSTANCE_REPORT, FlowDiagnostics.Result.SUCCEEDED);
        } catch (Exception | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.INSTANCE_REPORT, error);
            throw error;
        }
    }

    private synchronized void reportInternal(String generation, boolean cleared) throws Exception {
        JsonObject data = new JsonObject();
        data.addProperty("generation", generation);
        data.addProperty("cleared", cleared);
        data.addProperty("reportedAt", System.currentTimeMillis());
        Path target = file(generation), temp = root.resolve("instance-tmp-" + UUID.randomUUID());
        if (Files.isSymbolicLink(target)) throw new IllegalArgumentException("INSTANCE_PATH");
        Files.write(
                temp,
                Json.GSON.toJson(data).getBytes(StandardCharsets.UTF_8),
                StandardOpenOption.CREATE_NEW);
        Files.move(
                temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }

    public synchronized boolean allReported(String generation) throws Exception {
        try {
            boolean result = allReportedInternal(generation);
            trace.state(
                    FlowDiagnostics.Step.INSTANCE_RECEIPTS,
                    result ? FlowDiagnostics.Result.ALLOWED : FlowDiagnostics.Result.BLOCKED);
            return result;
        } catch (Exception | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.INSTANCE_RECEIPTS, error);
            throw error;
        }
    }

    private synchronized boolean allReportedInternal(String generation) throws Exception {
        UUID.fromString(generation);
        int count = 0;
        boolean all = true;
        try (DirectoryStream<Path> files =
                Files.newDirectoryStream(root, "instance-" + generation + "-*.json")) {
            for (Path file : files) {
                if (++count > 256 || Files.isSymbolicLink(file) || Files.size(file) > 1024)
                    return false;
                JsonObject entry =
                        Json.object(
                                new String(Files.readAllBytes(file), StandardCharsets.UTF_8), 1024);
                all &= entry.has("cleared") && entry.get("cleared").getAsBoolean();
            }
        }
        return count > 0 && all;
    }
}
