// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import java.io.IOException;

public final class NativeFailure extends IOException {
    public enum Api {
        SHELL_EXECUTE,
        LAUNCH_SERVICES,
        CF_URL,
        GIO_LAUNCH,
        DPAPI_READ,
        DPAPI_WRITE,
        KEYCHAIN_READ,
        KEYCHAIN_WRITE,
        KEYCHAIN_DELETE
    }

    public final Api api;
    public final long status;

    public NativeFailure(Api api, long status) {
        super("NATIVE_CALL_FAILED");
        this.api = api;
        this.status = status;
    }
}
