// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.fabric;

import net.fabricmc.loader.api.FabricLoader;
import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.screens.TitleScreen;

final class DevelopmentSmoke {
    private static int stage, ticks;

    static void tick(Minecraft client) {
        if (!FabricLoader.getInstance().isDevelopmentEnvironment()
                || !Boolean.getBoolean("mintauth.smoke")
                || System.getProperty("mintauth.testVaultRoot") == null) return;
        if (++ticks > 2400) throw new IllegalStateException("MintAuth development smoke timed out");
        if (stage == 0 && client.screen instanceof TitleScreen) {
            try {
                for (String name :
                        new String[] {
                            "net.minecraft.client.multiplayer.ClientHandshakePacketListenerImpl",
                            "net.minecraft.client.multiplayer.AccountProfileKeyPairManager",
                            "net.minecraft.client.gui.screens.ConnectScreen",
                            "net.minecraft.client.gui.screens.worldselection.WorldOpenFlows"
                        }) Class.forName(name);
                if (MintAuthClient.runtime() == null || !MintAuthClient.runtime().theme())
                    throw new IllegalStateException("Runtime unavailable");
                client.setScreen(new MintAuthScreen(client.screen));
                stage = 1;
            } catch (ClassNotFoundException error) {
                throw new IllegalStateException("Adapter class missing", error);
            }
        } else if (stage == 1 && client.screen instanceof MintAuthScreen) {
            System.out.println(
                    "MINTAUTH_DEVELOPMENT_SMOKE_PASSED: client mixins and account screen"
                            + " initialized; no online compatibility claim");
            stage = 2;
            client.stop();
        }
    }
}
