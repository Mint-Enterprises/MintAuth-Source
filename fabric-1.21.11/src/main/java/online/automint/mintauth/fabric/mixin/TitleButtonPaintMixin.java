// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.fabric.mixin;

import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.AbstractButton;

import online.automint.mintauth.fabric.FabricTitleTheme;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

@Mixin(AbstractButton.class)
public abstract class TitleButtonPaintMixin {
    @Inject(method = "renderWidget", at = @At("HEAD"), cancellable = true)
    private void mintauth$titlePaint(
            GuiGraphics graphics, int mouseX, int mouseY, float delta, CallbackInfo info) {
        if (FabricTitleTheme.suppressNativeTitlePaint()) info.cancel();
    }
}
