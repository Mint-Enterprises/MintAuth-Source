// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.fabric.mixin;

import com.mojang.authlib.services.FriendsService;

import net.minecraft.client.gui.screens.social.RemoteFriendListUpdateHandler;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Accessor;

@Mixin(RemoteFriendListUpdateHandler.class)
public interface FriendUpdatesAccess {
    @Accessor("friendsService")
    FriendsService mintauth$friendsApi();
}
