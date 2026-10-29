// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.fabric;

import net.minecraft.client.gui.screens.ConnectScreen;

import online.automint.mintauth.fabric.mixin.ConnectCleanupAccess;

final class ConnectionCleanup {
    private ConnectionCleanup() {}

    static void abort(ConnectScreen screen) {
        synchronized (screen) {
            ConnectCleanupAccess access = (ConnectCleanupAccess) screen;
            access.mintauth$aborted(true);
            var pending = access.mintauth$channelFuture();
            if (pending != null) {
                pending.cancel(true);
                access.mintauth$channelFuture(null);
            }
            var connection = access.mintauth$connection();
            if (connection != null) connection.disconnect(ConnectScreen.ABORT_CONNECTION);
        }
    }
}
