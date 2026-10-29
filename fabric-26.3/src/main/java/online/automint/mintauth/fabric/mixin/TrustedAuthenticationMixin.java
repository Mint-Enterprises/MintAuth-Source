// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.fabric.mixin;

import com.mojang.authlib.exceptions.AuthenticationException;
import com.mojang.authlib.exceptions.InvalidCredentialsException;
import com.mojang.authlib.minecraft.SessionService;

import net.minecraft.client.multiplayer.ClientHandshakePacketListenerImpl;

import online.automint.mintauth.core.Crypto;
import online.automint.mintauth.fabric.MintAuthClient;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Redirect;

import java.util.UUID;

@Mixin(ClientHandshakePacketListenerImpl.class)
public abstract class TrustedAuthenticationMixin {
    @Redirect(
            method = "authenticateServer",
            at =
                    @At(
                            value = "INVOKE",
                            target =
                                    "Lcom/mojang/authlib/minecraft/SessionService;joinServer(Ljava/util/UUID;Ljava/lang/String;Ljava/lang/String;)V"))
    private void mintauth$join(SessionService service, UUID uuid, String token, String digest)
            throws AuthenticationException {
        if (MintAuthClient.runtime() != null
                && !MintAuthClient.runtime()
                        .checkBeforeServerJoin(
                                uuid.toString().replace("-", "") + ":" + Crypto.tokenHash(token)))
            throw new AuthenticationException(MintAuthClient.runtime().joinFailureMessage());
        var runtime = MintAuthClient.runtime();
        if (runtime != null)
            runtime.authenticationEvent(
                    online.automint.mintauth.core.GameBridge.Progress.STARTED, null);
        try {
            service.joinServer(uuid, token, digest);
            if (runtime != null)
                runtime.authenticationEvent(
                        online.automint.mintauth.core.GameBridge.Progress.SUCCEEDED, null);
        } catch (InvalidCredentialsException rejected) {
            if (MintAuthClient.runtime() != null)
                MintAuthClient.runtime()
                        .invalidSession(
                                uuid.toString().replace("-", "") + ":" + Crypto.tokenHash(token));
            if (runtime != null)
                runtime.authenticationEvent(
                        online.automint.mintauth.core.GameBridge.Progress.FAILED, rejected);
            throw rejected;
        } catch (AuthenticationException | RuntimeException failure) {
            if (runtime != null)
                runtime.authenticationEvent(
                        online.automint.mintauth.core.GameBridge.Progress.FAILED, failure);
            throw failure;
        }
    }
}
