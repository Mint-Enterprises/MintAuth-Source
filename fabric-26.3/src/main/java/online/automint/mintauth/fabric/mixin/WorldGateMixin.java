// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.fabric.mixin;

import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.screens.worldselection.WorldOpenFlows;

import online.automint.mintauth.fabric.MintAuthClient;
import online.automint.mintauth.fabric.MintAuthScreen;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

@Mixin(WorldOpenFlows.class)
public abstract class WorldGateMixin {
    @Inject(
            method = {"openWorld", "createFreshLevel", "createLevelFromExistingSettings"},
            at = @At("HEAD"),
            cancellable = true)
    private void mintauth$world(CallbackInfo ci) {
        var runtime = MintAuthClient.runtime();
        if (runtime != null && !runtime.allowJoin()) {
            Minecraft mc = Minecraft.getInstance();
            mc.gui.setScreen(new MintAuthScreen(mc.gui.screen()));
            ci.cancel();
        }
    }
}
