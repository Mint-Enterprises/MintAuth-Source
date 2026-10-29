// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.fabric.mixin;

import net.minecraft.client.gui.GuiGraphicsExtractor;
import net.minecraft.client.gui.screens.TitleScreen;

import online.automint.mintauth.fabric.FabricTitleTheme;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

@Mixin(TitleScreen.class)
public abstract class TitleThemeMixin {
    @Inject(method = "extractRenderState", at = @At("HEAD"), cancellable = true)
    private void mintauth$title(
            GuiGraphicsExtractor graphics, int mouseX, int mouseY, float delta, CallbackInfo info) {
        if (FabricTitleTheme.render((TitleScreen) (Object) this, graphics, mouseX, mouseY, delta))
            info.cancel();
    }
}
