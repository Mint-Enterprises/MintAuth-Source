// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.fabric;

import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.fabric.api.client.event.lifecycle.v1.ClientLifecycleEvents;
import net.fabricmc.fabric.api.client.event.lifecycle.v1.ClientTickEvents;
import net.fabricmc.fabric.api.client.screen.v1.ScreenEvents;
import net.fabricmc.fabric.api.client.screen.v1.Screens;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.client.gui.screens.TitleScreen;
import net.minecraft.client.gui.screens.multiplayer.JoinMultiplayerScreen;
import net.minecraft.client.gui.screens.options.OptionsScreen;
import net.minecraft.client.gui.screens.worldselection.SelectWorldScreen;
import net.minecraft.network.chat.Component;

import online.automint.mintauth.core.MintAuthRuntime;

public final class MintAuthClient implements ClientModInitializer {
    private static volatile MintAuthRuntime runtime;

    public static MintAuthRuntime runtime() {
        return runtime;
    }

    private static boolean themed(Screen screen) {
        return screen instanceof TitleScreen
                || screen instanceof OptionsScreen
                || screen instanceof JoinMultiplayerScreen
                || screen instanceof SelectWorldScreen;
    }

    @Override
    public void onInitializeClient() {
        ClientLifecycleEvents.CLIENT_STARTED.register(
                client -> {
                    org.slf4j.LoggerFactory.getLogger("MintAuth")
                            .info(
                                    "[MintAuth] step=CLIENT_BOOTSTRAP result=STARTED"
                                            + " target=fabric-26.3");
                    try {
                        String testRoot =
                                net.fabricmc.loader.api.FabricLoader.getInstance()
                                                .isDevelopmentEnvironment()
                                        ? System.getProperty("mintauth.testVaultRoot")
                                        : null;
                        runtime =
                                testRoot == null
                                        ? new MintAuthRuntime(new FabricGameBridge(client))
                                        : new MintAuthRuntime(
                                                new FabricGameBridge(client),
                                                java.nio.file.Paths.get(testRoot));
                        var loader = net.fabricmc.loader.api.FabricLoader.getInstance();
                        var origin = loader.getModContainer("mintauth").orElseThrow().getOrigin();
                        if (origin.getPaths().size() == 1)
                            runtime.configureUpdates(
                                    "fabric-26.3", loader.getGameDir(), origin.getPaths().get(0));
                    } catch (Exception | LinkageError e) {
                        org.slf4j.LoggerFactory.getLogger("MintAuth")
                                .warn(
                                        "[MintAuth] step=CLIENT_BOOTSTRAP result=FAILED"
                                                + " target=fabric-26.3");
                        MintAuthRuntime.logBootstrapFailure(
                                e,
                                line -> org.slf4j.LoggerFactory.getLogger("MintAuth").warn(line));
                        throw new IllegalStateException(
                                "MintAuth secure storage could not initialize. See sanitized"
                                    + " MintAuth trace logs.");
                    }
                });
        ClientLifecycleEvents.CLIENT_STOPPING.register(
                client -> {
                    if (runtime != null) runtime.close();
                });
        ClientTickEvents.END_CLIENT_TICK.register(
                client -> {
                    if (runtime != null) {
                        runtime.tick();
                    }
                    DevelopmentSmoke.tick(client);
                });
        ScreenEvents.AFTER_INIT.register(
                (client, screen, width, height) -> {
                    if (!themed(screen)) return;
                    var widgets = Screens.getWidgets(screen);
                    boolean title = screen instanceof TitleScreen;
                    int actionWidth = title ? 104 : 72, actionHeight = title ? 20 : 16;
                    int x = width - actionWidth - 8, y = title ? 8 : 4;
                    widgets.add(
                            Button.builder(
                                            Component.literal("MintAuth"),
                                            button ->
                                                    client.gui.setScreen(
                                                            new MintAuthScreen(screen)))
                                    .bounds(x, y, actionWidth, actionHeight)
                                    .build());
                    ScreenEvents.afterBackground(screen)
                            .register(
                                    (s, g, mouseX, mouseY, delta) -> {
                                        if (runtime != null
                                                && runtime.theme()
                                                && !(s instanceof TitleScreen)) {
                                            g.fill(0, 0, width, height, 0x50132a18);
                                            g.fill(0, 0, width, 2, 0xffa6ed83);
                                        }
                                        if (runtime != null
                                                && runtime.activeIgn() != null
                                                && !(s instanceof TitleScreen && runtime.theme()))
                                            g.text(
                                                    client.font,
                                                    "MintAuth: " + runtime.activeIgn(),
                                                    8,
                                                    8,
                                                    0xffa6ed83);
                                    });
                });
    }
}
