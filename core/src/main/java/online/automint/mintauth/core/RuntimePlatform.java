// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import java.util.Locale;

final class RuntimePlatform {
    private RuntimePlatform() {}

    static String identifier(String osName, String architecture) {
        String os = osName.toLowerCase(Locale.ROOT);
        String arch = architecture.toLowerCase(Locale.ROOT);
        boolean x64 = arch.equals("amd64") || arch.equals("x86_64");
        if (os.contains("win") && !os.contains("darwin") && x64) return "WINDOWS_X64";
        if (os.contains("linux") && x64) return "LINUX_X64";
        if (os.contains("mac") || os.contains("darwin")) {
            if (x64) return "MACOS_X64";
            if (arch.equals("aarch64") || arch.equals("arm64")) return "MACOS_ARM64";
        }
        throw new IllegalStateException("PLATFORM_UNSUPPORTED");
    }
}
