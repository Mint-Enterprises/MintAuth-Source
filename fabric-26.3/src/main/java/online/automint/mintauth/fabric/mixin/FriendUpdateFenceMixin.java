// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.fabric.mixin;

import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.screens.social.RemoteFriendListUpdateHandler;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Redirect;

@Mixin(RemoteFriendListUpdateHandler.class)
public abstract class FriendUpdateFenceMixin {
    @Redirect(
            method = {"notifyListeners", "detectChangesAndShowToast", "emitToastWithSkin"},
            at =
                    @At(
                            value = "INVOKE",
                            target =
                                    "Lnet/minecraft/client/Minecraft;execute(Ljava/lang/Runnable;)V"))
    private void mintauth$fence(Minecraft client, Runnable task) {
        client.execute(
                () -> {
                    if (((ClientIdentityAccess) client).mintauth$friendUpdates() == (Object) this)
                        task.run();
                });
    }
}
