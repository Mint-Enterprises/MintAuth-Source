// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.fabric.mixin;

import com.mojang.authlib.minecraft.UserApiService;

import net.minecraft.client.Minecraft;
import net.minecraft.client.User;
import net.minecraft.client.gui.screens.social.PlayerSocialManager;
import net.minecraft.client.gui.screens.social.RemoteFriendListUpdateHandler;
import net.minecraft.client.multiplayer.ProfileKeyPairManager;
import net.minecraft.client.multiplayer.chat.report.ReportingContext;
import net.minecraft.client.telemetry.ClientTelemetryManager;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Mutable;
import org.spongepowered.asm.mixin.gen.Accessor;

import java.util.concurrent.CompletableFuture;

@Mixin(Minecraft.class)
public interface ClientIdentityAccess {
    @Accessor("remoteFriendListUpdateHandler")
    RemoteFriendListUpdateHandler mintauth$friendUpdates();

    @Mutable
    @Accessor("remoteFriendListUpdateHandler")
    void mintauth$friendUpdates(RemoteFriendListUpdateHandler value);

    @Accessor("user")
    User mintauth$user();

    @Mutable
    @Accessor("user")
    void mintauth$user(User value);

    @Accessor("userApiService")
    UserApiService mintauth$api();

    @Mutable
    @Accessor("userApiService")
    void mintauth$api(UserApiService value);

    @Accessor("userPropertiesFuture")
    CompletableFuture<UserApiService.UserProperties> mintauth$properties();

    @Mutable
    @Accessor("userPropertiesFuture")
    void mintauth$properties(CompletableFuture<UserApiService.UserProperties> value);

    @Accessor("profileFuture")
    CompletableFuture<?> mintauth$profile();

    @Mutable
    @Accessor("profileFuture")
    void mintauth$profile(CompletableFuture<?> value);

    @Accessor("profileKeyPairManager")
    ProfileKeyPairManager mintauth$keys();

    @Mutable
    @Accessor("profileKeyPairManager")
    void mintauth$keys(ProfileKeyPairManager value);

    @Accessor("playerSocialManager")
    PlayerSocialManager mintauth$social();

    @Mutable
    @Accessor("playerSocialManager")
    void mintauth$social(PlayerSocialManager value);

    @Accessor("telemetryManager")
    ClientTelemetryManager mintauth$telemetry();

    @Mutable
    @Accessor("telemetryManager")
    void mintauth$telemetry(ClientTelemetryManager value);

    @Accessor("reportingContext")
    ReportingContext mintauth$reports();

    @Accessor("reportingContext")
    void mintauth$reports(ReportingContext value);
}
