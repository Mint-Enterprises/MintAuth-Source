// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.fabric.mixin;

import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.screens.ConnectScreen;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.client.multiplayer.ServerData;
import net.minecraft.client.multiplayer.TransferState;
import net.minecraft.client.multiplayer.resolver.ServerAddress;

import online.automint.mintauth.fabric.MintAuthClient;
import online.automint.mintauth.fabric.MintAuthScreen;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

@Mixin(ConnectScreen.class)
public abstract class JoinGateMixin {
    @Inject(method = "startConnecting", at = @At("HEAD"), cancellable = true)
    private static void mintauth$gate(
            Screen parent,
            Minecraft client,
            ServerAddress address,
            ServerData server,
            boolean quickPlay,
            TransferState transfer,
            CallbackInfo ci) {
        var runtime = MintAuthClient.runtime();
        if (runtime == null) return;
        if (!runtime.allowJoin()) {
            client.setScreen(new MintAuthScreen(parent));
            ci.cancel();
            return;
        }
        if (transfer == null) runtime.rememberDestination(server.ip);
    }
}
