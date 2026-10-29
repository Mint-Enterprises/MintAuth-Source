// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

final class OfflineAllowance {
    private OfflineAllowance() {}

    static boolean persisted(long now, long checkedAt, long lastSeen, long expiresAt) {
        return checkedAt > 0 && now + 5000 >= Math.max(checkedAt, lastSeen) && expiresAt > now;
    }

    static long deadline(long now, long nano, long expiresAt) {
        long remaining = Math.max(0, Math.min(900000, expiresAt - now));
        return nano + java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(remaining);
    }
}
