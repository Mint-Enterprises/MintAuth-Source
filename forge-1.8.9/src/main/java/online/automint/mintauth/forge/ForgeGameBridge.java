// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.forge;

import com.mojang.authlib.GameProfile;
import com.mojang.authlib.exceptions.InvalidCredentialsException;
import com.mojang.authlib.minecraft.MinecraftSessionService;
import com.mojang.authlib.properties.PropertyMap;

import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.GuiMainMenu;
import net.minecraft.client.multiplayer.GuiConnecting;
import net.minecraft.client.multiplayer.ServerData;
import net.minecraft.network.NetworkManager;
import net.minecraft.util.ChatComponentText;
import net.minecraft.util.Session;
import net.minecraftforge.fml.relauncher.ReflectionHelper;

import online.automint.mintauth.core.Crypto;
import online.automint.mintauth.core.GameBridge;

import java.lang.reflect.*;

final class ForgeGameBridge implements GameBridge {
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
        org.apache.logging.log4j.LogManager.getLogger("MintAuth").info(line);
    }

    @Override
    public void logFailureDiagnostic(String line) {
        org.apache.logging.log4j.LogManager.getLogger("MintAuth").warn(line);
    }

    @Override
    public void openWebsite(java.net.URI uri) throws Exception {
        online.automint.mintauth.core.NativeStores.openWebsite(uri.toASCIIString());
    }

    @Override
    public void copyWebsiteLink(String link) {
        net.minecraft.client.gui.GuiScreen.setClipboardString(link);
    }

    private final Minecraft client;
    private final Session launcher;
    private final PropertyMap launcherProperties = new PropertyMap();
    private final Field session, properties;

    ForgeGameBridge(Minecraft client) throws Exception {
        this.client = client;
        session = ReflectionHelper.findField(Minecraft.class, "session", "field_71449_j");
        properties =
                ReflectionHelper.findField(Minecraft.class, "profileProperties", "field_181038_N");
        launcher = client.getSession();
        launcherProperties.putAll((PropertyMap) properties.get(client));
        Field service =
                ReflectionHelper.findField(Minecraft.class, "sessionService", "field_152355_az");
        final MinecraftSessionService delegate = client.getSessionService();
        MinecraftSessionService wrapped =
                (MinecraftSessionService)
                        Proxy.newProxyInstance(
                                MinecraftSessionService.class.getClassLoader(),
                                new Class<?>[] {MinecraftSessionService.class},
                                (proxy, method, args) -> {
                                    if (method.getDeclaringClass() == Object.class) {
                                        if (method.getName().equals("toString"))
                                            return "MintAuth session service";
                                        if (method.getName().equals("hashCode"))
                                            return System.identityHashCode(proxy);
                                        if (method.getName().equals("equals"))
                                            return proxy == args[0];
                                    }
                                    boolean joining = method.getName().equals("joinServer");
                                    if (joining)
                                        traceStage(Stage.AUTHENTICATION, Progress.STARTED, null);
                                    if (joining
                                            && args != null
                                            && args.length >= 2
                                            && MintAuthMod.runtime() != null) {
                                        GameProfile profile = (GameProfile) args[0];
                                        if (profile.getId() != null
                                                && !MintAuthMod.runtime()
                                                        .checkBeforeServerJoin(
                                                                profile.getId()
                                                                                .toString()
                                                                                .replace("-", "")
                                                                        + ":"
                                                                        + Crypto.tokenHash(
                                                                                (String)
                                                                                        args[1]))) {
                                            com.mojang.authlib.exceptions.AuthenticationException
                                                    blocked =
                                                            new com.mojang.authlib.exceptions
                                                                    .AuthenticationException(
                                                                    MintAuthMod.runtime()
                                                                            .joinFailureMessage());
                                            traceStage(
                                                    Stage.AUTHENTICATION, Progress.FAILED, blocked);
                                            throw blocked;
                                        }
                                        if (profile.getId() != null && args.length == 3) {
                                            try {
                                                if (MintAuthMod.runtime()
                                                        .joinLegacyMinecraft(
                                                                profile.getId()
                                                                        .toString()
                                                                        .replace("-", ""),
                                                                (String) args[1],
                                                                (String) args[2])) return null;
                                            } catch (
                                                    online.automint.mintauth.core.MinecraftJoin
                                                                    .Failure
                                                            failure) {
                                                throw new com.mojang.authlib.exceptions
                                                        .AuthenticationException(
                                                        failure.getMessage());
                                            } catch (java.io.IOException network) {
                                                traceStage(
                                                        Stage.AUTHENTICATION,
                                                        Progress.FAILED,
                                                        network);
                                                throw new com.mojang.authlib.exceptions
                                                        .AuthenticationException(
                                                        "Could not securely contact Minecraft"
                                                            + " authentication. Try again."
                                                            + " [MC_NETWORK]");
                                            }
                                        }
                                    }
                                    try {
                                        Object result = method.invoke(delegate, args);
                                        if (joining)
                                            traceStage(
                                                    Stage.AUTHENTICATION, Progress.SUCCEEDED, null);
                                        return result;
                                    } catch (InvocationTargetException error) {
                                        Throwable cause = error.getCause();
                                        if (joining)
                                            traceStage(
                                                    Stage.AUTHENTICATION, Progress.FAILED, cause);
                                        if (method.getName().equals("joinServer")
                                                && cause instanceof InvalidCredentialsException
                                                && args != null
                                                && args.length >= 2) {
                                            GameProfile profile = (GameProfile) args[0];
                                            if (profile.getId() != null
                                                    && MintAuthMod.runtime() != null)
                                                MintAuthMod.runtime()
                                                        .invalidSession(
                                                                profile.getId()
                                                                                .toString()
                                                                                .replace("-", "")
                                                                        + ":"
                                                                        + Crypto.tokenHash(
                                                                                (String) args[1]));
                                        }
                                        throw cause;
                                    }
                                });
        service.set(client, wrapped);
    }

    public void onClient(Runnable action) {
        client.addScheduledTask(action);
    }

    public boolean worldOpen() {
        return client.theWorld != null
                || client.getNetHandler() != null
                || client.currentScreen instanceof GuiConnecting;
    }

    @Override
    public boolean multiplayerWorldOpen() {
        return worldOpen() && !client.isSingleplayer();
    }


    public String currentFingerprint() {
        Session user = client.getSession();
        return user.getPlayerID().replace("-", "") + ":" + Crypto.tokenHash(user.getToken());
    }

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
        if (!client.isCallingFromMinecraftThread() || worldOpen())
            throw new IllegalStateException("DISCONNECT_FIRST");
        session.set(client, new Session(identity.ign, identity.uuid, identity.token(), "mojang"));
        ((PropertyMap) properties.get(client)).clear();
        client.setServerData(null);
    }

    public void restoreLauncher() throws Exception {
        traceStage(Stage.LAUNCHER, Progress.STARTED, null);
        try {
            restoreLauncherInternal();
            traceStage(Stage.LAUNCHER, Progress.SUCCEEDED, null);

        } catch (Exception | LinkageError error) {
            traceStage(Stage.LAUNCHER, Progress.FAILED, error);
            throw error;
        }
    }

    private void restoreLauncherInternal() throws Exception {
        if (worldOpen()) throw new IllegalStateException("DISCONNECT_FIRST");
        session.set(client, launcher);
        PropertyMap map = (PropertyMap) properties.get(client);
        map.clear();
        map.putAll(launcherProperties);
        client.setServerData(null);
    }

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
        if (client.currentScreen instanceof GuiConnecting) {
            try {
                ReflectionHelper.findField(GuiConnecting.class, "cancel", "field_146373_h")
                        .setBoolean(client.currentScreen, true);
                NetworkManager network =
                        (NetworkManager)
                                ReflectionHelper.findField(
                                                GuiConnecting.class,
                                                "networkManager",
                                                "field_146371_g")
                                        .get(client.currentScreen);
                if (network != null) network.closeChannel(new ChatComponentText(reason));
            } catch (ReflectiveOperationException error) {
                traceStage(Stage.CONNECTION, Progress.FAILED, error);
            }
        }
        if (client.theWorld != null) client.theWorld.sendQuittingDisconnectingPacket();
        client.loadWorld(null);
        client.displayGuiScreen(new GuiMainMenu());
        after.run();
    }

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
        ServerData data = new ServerData("MintAuth reconnect", destination, false);
        client.displayGuiScreen(new GuiConnecting(new GuiMainMenu(), client, data));
    }
}
