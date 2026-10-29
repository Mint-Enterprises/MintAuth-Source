// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.fabric.mixin;

import net.minecraft.client.Minecraft;

import online.automint.mintauth.fabric.MintAuthClient;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

@Mixin(Minecraft.class)
public abstract class RealmsGateMixin {
    @Inject(method = "allowsRealms", at = @At("RETURN"), cancellable = true)
    private void mintauth$realms(CallbackInfoReturnable<Boolean> result) {
        if (MintAuthClient.runtime() != null)
            MintAuthClient.runtime().logRealmsGate(MintAuthClient.runtime().activeId() == null);
        if (MintAuthClient.runtime() != null && MintAuthClient.runtime().activeId() != null)
            result.setReturnValue(false);
    }
}
