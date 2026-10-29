// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.fabric.mixin;

import io.netty.channel.ChannelFuture;

import net.minecraft.client.gui.screens.ConnectScreen;
import net.minecraft.network.Connection;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Accessor;

@Mixin(ConnectScreen.class)
public interface ConnectCleanupAccess {
    @Accessor("aborted")
    void mintauth$aborted(boolean value);

    @Accessor("connection")
    Connection mintauth$connection();

    @Accessor("channelFuture")
    ChannelFuture mintauth$channelFuture();

    @Accessor("channelFuture")
    void mintauth$channelFuture(ChannelFuture value);
}
