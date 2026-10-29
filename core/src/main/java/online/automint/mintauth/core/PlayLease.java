// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.UUID;

public final class PlayLease implements AutoCloseable {
    private final Path root;
    private volatile FlowDiagnostics trace = FlowDiagnostics.silent();

    void setDiagnostics(FlowDiagnostics value) {
        trace = value;
    }

    private FileChannel channel;
    private FileLock lock;
    private String uuid;
    private final String instance = UUID.randomUUID().toString();

    public PlayLease(Path root) {
        this.root = root;
    }

    private Path file(String uuid, String suffix) {
        if (!uuid.matches("[a-f0-9]{32}")) throw new IllegalArgumentException("UUID_INVALID");
        return root.resolve("play-" + uuid + suffix);
    }

    public synchronized boolean acquire(String uuid) throws Exception {
        trace.step(FlowDiagnostics.Step.LEASE_ACQUIRE, FlowDiagnostics.Result.STARTED);
        try {
            boolean result = acquireInternal(uuid);
            trace.step(
                    FlowDiagnostics.Step.LEASE_ACQUIRE,
                    result ? FlowDiagnostics.Result.ALLOWED : FlowDiagnostics.Result.BLOCKED);
            return result;
        } catch (Exception | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.LEASE_ACQUIRE, error);
            throw error;
        }
    }

    private synchronized boolean acquireInternal(String uuid) throws Exception {
        if (uuid.equals(this.uuid) && lock != null && lock.isValid()) return true;
        Path p = file(uuid, ".lock");
        if (Files.isSymbolicLink(p)) throw new IllegalArgumentException("LEASE_PATH");
        FileChannel nextChannel =
                FileChannel.open(p, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        FileLock nextLock;
        try {
            nextLock = nextChannel.tryLock();
        } catch (OverlappingFileLockException ignored) {
            nextLock = null;
        }
        if (nextLock == null) {
            nextChannel.close();
            return false;
        }
        try {
            Path owner = file(uuid, ".owner");
            if (Files.isSymbolicLink(owner)) throw new IllegalArgumentException("LEASE_PATH");
            Files.write(
                    owner,
                    instance.getBytes(StandardCharsets.US_ASCII),
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING);
        } catch (Exception error) {
            nextLock.release();
            nextChannel.close();
            throw error;
        }
        close();
        channel = nextChannel;
        lock = nextLock;
        this.uuid = uuid;
        return true;
    }

    public void requestMove(String uuid) throws Exception {
        trace.step(FlowDiagnostics.Step.LEASE_MOVE, FlowDiagnostics.Result.STARTED);
        try {
            requestMoveInternal(uuid);
            trace.step(FlowDiagnostics.Step.LEASE_MOVE, FlowDiagnostics.Result.SUCCEEDED);
        } catch (Exception | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.LEASE_MOVE, error);
            throw error;
        }
    }

    private void requestMoveInternal(String uuid) throws Exception {
        Path owner = file(uuid, ".owner");
        if (Files.isSymbolicLink(owner) || Files.size(owner) > 64)
            throw new IllegalArgumentException("LEASE_INVALID");
        Files.write(
                file(uuid, ".move"),
                Files.readAllBytes(owner),
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING);
    }

    public synchronized boolean moveRequested() {
        try {
            boolean result = moveRequestedInternal();
            trace.state(
                    FlowDiagnostics.Step.LEASE_MOVE,
                    result ? FlowDiagnostics.Result.ALLOWED : FlowDiagnostics.Result.BLOCKED);
            return result;
        } catch (RuntimeException | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.LEASE_MOVE, error);
            throw error;
        }
    }

    private synchronized boolean moveRequestedInternal() {
        try {
            Path p = uuid == null ? null : file(uuid, ".move");
            return p != null
                    && Files.exists(p)
                    && Files.size(p) < 64
                    && new String(Files.readAllBytes(p), StandardCharsets.US_ASCII)
                            .equals(instance);
        } catch (Exception error) {
            trace.failure(FlowDiagnostics.Step.LEASE_MOVE, error);
            return false;
        }
    }

    @Override
    public synchronized void close() {
        try {
            closeInternal();
            trace.state(FlowDiagnostics.Step.LEASE_RELEASE, FlowDiagnostics.Result.SUCCEEDED);
        } catch (RuntimeException | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.LEASE_RELEASE, error);
            throw error;
        }
    }

    private synchronized void closeInternal() {
        try {
            if (lock != null) lock.release();
        } catch (Exception error) {
            trace.failure(FlowDiagnostics.Step.LEASE_RELEASE, error);
        }
        try {
            if (channel != null) channel.close();
        } catch (Exception error) {
            trace.failure(FlowDiagnostics.Step.LEASE_RELEASE, error);
        }
        lock = null;
        channel = null;
        uuid = null;
    }
}
