// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.fabric.mixin;

import com.mojang.authlib.minecraft.UserApiService;

import net.minecraft.client.multiplayer.AccountProfileKeyPairManager;
import net.minecraft.util.CryptException;
import net.minecraft.world.entity.player.ProfileKeyPair;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Invoker;

import java.io.IOException;

@Mixin(AccountProfileKeyPairManager.class)
public interface ProfileKeyFetchAccess {
    @Invoker("fetchProfileKeyPair")
    ProfileKeyPair mintauth$fetch(UserApiService service) throws IOException, CryptException;
}
