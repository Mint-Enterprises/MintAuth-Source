// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.fabric;

import com.mojang.authlib.minecraft.UserApiService;
import com.mojang.authlib.services.FriendsService;
import com.mojang.authlib.services.MinecraftServicesDiscoveryService;

import net.minecraft.client.Minecraft;
import net.minecraft.client.User;
import net.minecraft.client.gui.screens.ConnectScreen;
import net.minecraft.client.gui.screens.TitleScreen;
import net.minecraft.client.gui.screens.social.PlayerSocialManager;
import net.minecraft.client.gui.screens.social.RemoteFriendListUpdateHandler;
import net.minecraft.client.multiplayer.ProfileKeyPairManager;
import net.minecraft.client.multiplayer.ServerData;
import net.minecraft.client.multiplayer.chat.report.ReportEnvironment;
import net.minecraft.client.multiplayer.chat.report.ReportingContext;
import net.minecraft.client.multiplayer.resolver.ServerAddress;
import net.minecraft.client.telemetry.ClientTelemetryManager;
import net.minecraft.network.chat.Component;
import net.minecraft.util.Util;

import online.automint.mintauth.core.GameBridge;
import online.automint.mintauth.fabric.mixin.ClientIdentityAccess;
import online.automint.mintauth.fabric.mixin.FriendUpdatesAccess;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

final class FabricGameBridge implements GameBridge {
    private volatile Diagnostics diagnosticEvents = (stage, progress, error) -> {};

    @Override
    public void setDiagnostics(Diagnostics value) {
        diagnosticEvents = value;
    }

    private void traceStage(Stage stage, Progress progress, Throwable error) {
        try {
            diagnosticEvents.event(stage, progress, error);
        } catch (RuntimeException | LinkageError ignored) {
        }
    }

    @Override
    public void logDiagnostic(String line) {
        org.slf4j.LoggerFactory.getLogger("MintAuth").info(line);
    }

    @Override
    public void logFailureDiagnostic(String line) {
        org.slf4j.LoggerFactory.getLogger("MintAuth").warn(line);
    }

    @Override
    public void openWebsite(java.net.URI uri) throws Exception {
        online.automint.mintauth.core.NativeStores.openWebsite(uri.toASCIIString());
    }

    @Override
    public void copyWebsiteLink(String link) {
        client.keyboardHandler.setClipboard(link);
    }

    private final Minecraft client;
    private final ClientIdentityAccess access;
    private final User launcher;
    private final UserApiService launcherApi;
    private final ProfileKeyPairManager launcherKeys;
    private final PlayerSocialManager launcherSocial;
    private final ReportingContext launcherReports;
    private final FriendsService launcherFriends;
    private boolean mintActive;

    FabricGameBridge(Minecraft client) {
        this.client = client;
        access = (ClientIdentityAccess) client;
        launcher = access.mintauth$user();
        launcherApi = access.mintauth$api();
        launcherKeys = access.mintauth$keys();
        launcherSocial = access.mintauth$social();
        launcherReports = access.mintauth$reports();
        launcherFriends =
                ((FriendUpdatesAccess) (Object) access.mintauth$friendUpdates())
                        .mintauth$friendsApi();
    }

    static final class Prepared implements AutoCloseable {
        final User user;
        final UserApiService api;
        final UserApiService.UserProperties properties;
        final CompletableFuture<?> profile;
        final MemoryProfileKeys keys;
        final FriendsService friends;

        Prepared(
                User user,
                UserApiService api,
                UserApiService.UserProperties properties,
                CompletableFuture<?> profile,
                MemoryProfileKeys keys,
                FriendsService friends) {
            this.user = user;
            this.api = api;
            this.properties = properties;
            this.profile = profile;
            this.keys = keys;
            this.friends = friends;
        }

        public void close() {
            keys.close();
            profile.cancel(true);
        }
    }

    private static UUID uuid(String raw) {
        return UUID.fromString(
                raw.replaceFirst(
                        "([0-9a-fA-F]{8})([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{4})([0-9a-fA-F]{12})",
                        "$1-$2-$3-$4-$5"));
    }

    @Override
    public Object prepare(Identity identity) throws Exception {
        traceStage(Stage.PREPARE, Progress.STARTED, null);
        try {
            Object result = prepareInternal(identity);
            traceStage(Stage.PREPARE, Progress.SUCCEEDED, null);
            return result;
        } catch (Exception | LinkageError error) {
            traceStage(Stage.PREPARE, Progress.FAILED, error);
            throw error;
        }
    }

    private Object prepareInternal(Identity identity) throws Exception {
        UUID id = uuid(identity.uuid);
        var discovery = MinecraftServicesDiscoveryService.create(client.getProxy(), true);
        UserApiService api = discovery.createUserApiService(identity.token());
        traceStage(Stage.RESTRICTIONS, Progress.STARTED, null);
        var properties = api.fetchProperties();
        traceStage(Stage.RESTRICTIONS, Progress.SUCCEEDED, null);
        traceStage(Stage.PROFILE, Progress.STARTED, null);
        var profile = client.services().sessionService().fetchProfile(id, true);
        if (profile == null || !profile.profile().id().equals(id))
            throw new IllegalStateException("PROFILE_UNAVAILABLE");
        traceStage(Stage.PROFILE, Progress.SUCCEEDED, null);
        User user =
                new User(
                        profile.profile().name(),
                        id,
                        identity.token(),
                        Optional.empty(),
                        Optional.empty());
        MemoryProfileKeys keys = new MemoryProfileKeys(api, id, this::traceStage);
        traceStage(Stage.PROFILE_KEYS, Progress.STARTED, null);
        var signingKeys = keys.prepareKeyPair().get(15, TimeUnit.SECONDS);
        traceStage(
                Stage.PROFILE_KEYS,
                signingKeys.isEmpty() ? Progress.EMPTY : Progress.SUCCEEDED,
                null);
        return new Prepared(
                user,
                api,
                properties,
                CompletableFuture.completedFuture(profile),
                keys,
                discovery.createFriendsService(identity.token()));
    }

    @Override
    public void onClient(Runnable action) {
        client.execute(action);
    }

    @Override
    public String preparationWarning(Object value) {
        return value instanceof Prepared prepared
                        && prepared.keys.prepareKeyPair().getNow(Optional.empty()).isEmpty()
                ? "Signed-chat key unavailable; some servers may reject this session"
                : null;
    }

    @Override
    public boolean worldOpen() {
        return client.level != null
                || client.getConnection() != null
                || client.gui.screen() instanceof ConnectScreen;
    }

    @Override
    public boolean multiplayerWorldOpen() {
        return worldOpen() && client.getSingleplayerServer() == null;
    }


    @Override
    public String currentFingerprint() {
        User u = client.getUser();
        return u.getProfileId().toString().replace("-", "")
                + ":"
                + online.automint.mintauth.core.Crypto.tokenHash(u.getAccessToken());
    }

    private void discardMint() {
        traceStage(Stage.SESSION, Progress.STARTED, null);
        try {
            discardMintInternal();
            traceStage(Stage.SESSION, Progress.SUCCEEDED, null);

        } catch (RuntimeException | LinkageError error) {
            traceStage(Stage.SESSION, Progress.FAILED, error);
            throw error;
        }
    }

    private void discardMintInternal() {
        if (access.mintauth$keys() instanceof MemoryProfileKeys memory) memory.close();
        access.mintauth$social().getPresenceHandler().sendOfflinePresence();
        access.mintauth$friendUpdates().close();
        if (mintActive) {
            access.mintauth$profile().cancel(true);
            access.mintauth$properties().cancel(true);
        }
        access.mintauth$social().stopOnlineMode();
        access.mintauth$telemetry().close();
    }

    @Override
    public void install(Identity identity) throws Exception {
        traceStage(Stage.SESSION, Progress.STARTED, null);
        try {
            installInternal(identity);
            traceStage(Stage.SESSION, Progress.SUCCEEDED, null);

        } catch (Exception | LinkageError error) {
            traceStage(Stage.SESSION, Progress.FAILED, error);
            throw error;
        }
    }

    private void installInternal(Identity identity) throws Exception {
        throw new IllegalStateException("PREPARATION_REQUIRED");
    }

    @Override
    public void installPrepared(Identity identity, Object value) throws Exception {
        traceStage(Stage.SESSION, Progress.STARTED, null);
        try {
            installPreparedInternal(identity, value);
            traceStage(Stage.SESSION, Progress.SUCCEEDED, null);

        } catch (Exception | LinkageError error) {
            traceStage(Stage.SESSION, Progress.FAILED, error);
            throw error;
        }
    }

    private void installPreparedInternal(Identity identity, Object value) throws Exception {
        if (!client.isSameThread() || worldOpen() || !(value instanceof Prepared prepared))
            throw new IllegalStateException("SWITCH_STATE");
        client.disconnect(client.gui.screen(), false, false);
        discardMint();
        traceStage(Stage.SESSION, Progress.STARTED, null);
        access.mintauth$user(prepared.user);
        access.mintauth$api(prepared.api);
        access.mintauth$profile(prepared.profile);
        access.mintauth$properties(CompletableFuture.completedFuture(prepared.properties));
        traceStage(Stage.PROFILE_KEYS, Progress.STARTED, null);
        access.mintauth$keys(prepared.keys);
        traceStage(Stage.PROFILE_KEYS, Progress.SUCCEEDED, null);
        traceStage(Stage.SOCIAL, Progress.STARTED, null);
        var friends = new RemoteFriendListUpdateHandler(prepared.friends, client);
        access.mintauth$friendUpdates(friends);
        var social = new PlayerSocialManager(client, prepared.api, prepared.friends, friends);
        access.mintauth$social(social);
        if (social.isFriendListEnabled()) friends.start();
        traceStage(Stage.SOCIAL, Progress.SUCCEEDED, null);
        traceStage(Stage.REPORTING, Progress.STARTED, null);
        access.mintauth$reports(ReportingContext.create(ReportEnvironment.local(), prepared.api));
        traceStage(Stage.REPORTING, Progress.SUCCEEDED, null);
        traceStage(Stage.TELEMETRY, Progress.STARTED, null);
        access.mintauth$telemetry(new ClientTelemetryManager(client, prepared.api, prepared.user));
        traceStage(Stage.TELEMETRY, Progress.SUCCEEDED, null);
        mintActive = true;
    }

    @Override
    public void restoreLauncher() {
        traceStage(Stage.LAUNCHER, Progress.STARTED, null);
        try {
            restoreLauncherInternal();
            traceStage(Stage.LAUNCHER, Progress.SUCCEEDED, null);

        } catch (RuntimeException | LinkageError error) {
            traceStage(Stage.LAUNCHER, Progress.FAILED, error);
            throw error;
        }
    }

    private void restoreLauncherInternal() {
        if (worldOpen()) throw new IllegalStateException("DISCONNECT_FIRST");
        discardMint();
        access.mintauth$user(launcher);
        access.mintauth$api(launcherApi);
        access.mintauth$keys(launcherKeys);
        access.mintauth$reports(launcherReports);
        access.mintauth$profile(
                CompletableFuture.supplyAsync(
                                () ->
                                        client.services()
                                                .sessionService()
                                                .fetchProfile(launcher.getProfileId(), true),
                                Util.nonCriticalIoPool())
                        .whenComplete(
                                (value, error) ->
                                        traceStage(
                                                Stage.PROFILE,
                                                GameBridge.completion(value != null, error),
                                                error)));
        access.mintauth$properties(
                CompletableFuture.supplyAsync(
                                () -> {
                                    try {
                                        return launcherApi.fetchProperties();
                                    } catch (Exception e) {
                                        throw new java.util.concurrent.CompletionException(e);
                                    }
                                },
                                Util.nonCriticalIoPool())
                        .whenComplete(
                                (value, error) ->
                                        traceStage(
                                                Stage.RESTRICTIONS,
                                                GameBridge.completion(value != null, error),
                                                error)));
        var friends = new RemoteFriendListUpdateHandler(launcherFriends, client);
        access.mintauth$friendUpdates(friends);
        var social = new PlayerSocialManager(client, launcherApi, launcherFriends, friends);
        for (UUID hidden : launcherSocial.getHiddenPlayers()) social.hidePlayer(hidden);
        access.mintauth$social(social);
        if (social.isFriendListEnabled()) friends.start();
        access.mintauth$telemetry(new ClientTelemetryManager(client, launcherApi, launcher));
        mintActive = false;
    }

    @Override
    public void leaveWorld(String reason, Runnable after) {
        traceStage(Stage.CONNECTION, Progress.STARTED, null);
        try {
            leaveWorldInternal(reason, after);
            traceStage(Stage.CONNECTION, Progress.SUCCEEDED, null);

        } catch (RuntimeException | LinkageError error) {
            traceStage(Stage.CONNECTION, Progress.FAILED, error);
            throw error;
        }
    }

    private void leaveWorldInternal(String reason, Runnable after) {
        if (client.gui.screen() instanceof ConnectScreen connecting)
            ConnectionCleanup.abort(connecting);
        if (client.level != null) client.disconnectFromWorld(Component.literal(reason));
        else if (client.getConnection() != null) client.disconnectWithProgressScreen();
        if (client.gui.screen() instanceof ConnectScreen connecting) {
            ConnectionCleanup.abort(connecting);
            client.gui.setScreen(new TitleScreen());
        }
        after.run();
    }

    @Override
    public void connect(String destination) {
        traceStage(Stage.CONNECTION, Progress.STARTED, null);
        try {
            connectInternal(destination);
            traceStage(Stage.CONNECTION, Progress.SUCCEEDED, null);

        } catch (RuntimeException | LinkageError error) {
            traceStage(Stage.CONNECTION, Progress.FAILED, error);
            throw error;
        }
    }

    private void connectInternal(String destination) {
        ConnectScreen.startConnecting(
                new TitleScreen(),
                client,
                ServerAddress.parseString(destination),
                new ServerData("MintAuth reconnect", destination, ServerData.Type.OTHER),
                false,
                null);
    }
}
