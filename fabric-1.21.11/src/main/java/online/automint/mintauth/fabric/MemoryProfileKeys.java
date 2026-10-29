// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.fabric;

import com.mojang.authlib.minecraft.UserApiService;

import net.minecraft.client.multiplayer.AccountProfileKeyPairManager;
import net.minecraft.client.multiplayer.ProfileKeyPairManager;
import net.minecraft.util.Util;
import net.minecraft.world.entity.player.ProfileKeyPair;

import online.automint.mintauth.fabric.mixin.ProfileKeyFetchAccess;

import java.nio.file.Path;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

final class MemoryProfileKeys implements ProfileKeyPairManager, AutoCloseable {
    private final UserApiService api;
    private final online.automint.mintauth.core.GameBridge.Diagnostics diagnosticEvents;

    private void traceKey(
            online.automint.mintauth.core.GameBridge.Stage stage,
            online.automint.mintauth.core.GameBridge.Progress progress,
            Throwable error) {
        try {
            diagnosticEvents.event(stage, progress, error);
        } catch (RuntimeException | LinkageError ignored) {
        }
    }

    private final ProfileKeyFetchAccess fetcher;
    private volatile boolean closed;
    private volatile Instant refreshAfter = Instant.EPOCH;
    private CompletableFuture<Optional<ProfileKeyPair>> future =
            CompletableFuture.completedFuture(Optional.empty());

    MemoryProfileKeys(UserApiService api, UUID uuid) {
        this(api, uuid, (stage, progress, error) -> {});
    }

    MemoryProfileKeys(
            UserApiService api,
            UUID uuid,
            online.automint.mintauth.core.GameBridge.Diagnostics diagnostics) {
        this.diagnosticEvents = diagnostics;
        this.api = api;
        fetcher =
                (ProfileKeyFetchAccess)
                        new AccountProfileKeyPairManager(
                                api, uuid, Path.of("mintauth-memory-only"));
    }

    @Override
    public synchronized CompletableFuture<Optional<ProfileKeyPair>> prepareKeyPair() {
        if (closed) return CompletableFuture.completedFuture(Optional.empty());
        if (!future.isDone() || Instant.now().isBefore(refreshAfter)) return future;
        traceKey(
                online.automint.mintauth.core.GameBridge.Stage.KEY_FETCH,
                online.automint.mintauth.core.GameBridge.Progress.STARTED,
                null);
        refreshAfter = Instant.now().plusSeconds(3600);
        future =
                CompletableFuture.supplyAsync(
                        () -> {
                            try {
                                ProfileKeyPair key = fetcher.mintauth$fetch(api);
                                traceKey(
                                        online.automint.mintauth.core.GameBridge.Stage.KEY_FETCH,
                                        closed
                                                ? online.automint.mintauth.core.GameBridge.Progress
                                                        .CANCELLED
                                                : key == null
                                                        ? online.automint.mintauth.core.GameBridge
                                                                .Progress.EMPTY
                                                        : online.automint.mintauth.core.GameBridge
                                                                .Progress.SUCCEEDED,
                                        null);
                                return closed ? Optional.empty() : Optional.ofNullable(key);
                            } catch (Exception e) {
                                traceKey(
                                        online.automint.mintauth.core.GameBridge.Stage.KEY_FETCH,
                                        closed
                                                ? online.automint.mintauth.core.GameBridge.Progress
                                                        .CANCELLED
                                                : online.automint.mintauth.core.GameBridge.Progress
                                                        .FAILED,
                                        closed ? null : e);
                                return Optional.empty();
                            }
                        },
                        Util.nonCriticalIoPool());
        return future;
    }

    @Override
    public boolean shouldRefreshKeyPair() {
        return !closed && future.isDone() && Instant.now().isAfter(refreshAfter);
    }

    @Override
    public synchronized void close() {
        closed = true;
        future.cancel(true);
        future = CompletableFuture.completedFuture(Optional.empty());
        traceKey(
                online.automint.mintauth.core.GameBridge.Stage.KEY_CLEAR,
                online.automint.mintauth.core.GameBridge.Progress.SUCCEEDED,
                null);
    }
}
