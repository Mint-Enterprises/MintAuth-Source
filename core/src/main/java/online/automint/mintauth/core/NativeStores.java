// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import com.sun.jna.*;
import com.sun.jna.platform.win32.Crypt32Util;
import com.sun.jna.ptr.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public final class NativeStores {
    private NativeStores() {}

    public static SecretStore forPlatform(Path root) {
        if (!NativeRuntime.owns(NativeStores.class)) return NativeRuntime.store(root);
        String os = System.getProperty("os.name").toLowerCase(Locale.ROOT);
        if (os.contains("mac") || os.contains("darwin")) return new Mac();
        if (os.contains("win")) return new Windows(root);
        return new Linux();
    }

    public static String windowsDataRoot() throws Exception {
        if (!NativeRuntime.owns(NativeStores.class)) return NativeRuntime.windowsDataRoot();
        return com.sun.jna.platform.win32.Shell32Util.getKnownFolderPath(
                com.sun.jna.platform.win32.KnownFolders.FOLDERID_LocalAppData);
    }

    interface BrowserCF extends Library {
        Pointer CFURLCreateWithBytes(
                Pointer allocator, byte[] bytes, long length, int encoding, Pointer base);

        void CFRelease(Pointer value);
    }

    interface LaunchServices extends Library {
        int LSOpenCFURLRef(Pointer url, PointerByReference launched);
    }

    interface BrowserGio extends Library {
        boolean g_app_info_launch_default_for_uri(
                String uri, Pointer context, PointerByReference error);
    }

    public static void openWebsite(String url) throws Exception {
        if (url == null
                || !url.matches(
                        "https://automint\\.online/(?:mintauth/link(?:#code=[A-HJ-NP-Z2-9]{8})?|dashboard/accounts\\?action=add|download/mintauth)"))
            throw new IOException("WEBSITE_URL_INVALID");
        if (!NativeRuntime.owns(NativeStores.class)) {
            NativeRuntime.openWebsite(url);
            return;
        }
        String os = System.getProperty("os.name").toLowerCase(Locale.ROOT);
        if (os.contains("mac") || os.contains("darwin")) {
            BrowserCF cf = Native.load("CoreFoundation", BrowserCF.class);
            byte[] bytes = url.getBytes(StandardCharsets.UTF_8);
            Pointer value = cf.CFURLCreateWithBytes(null, bytes, bytes.length, 0x08000100, null);
            if (value == null) throw new NativeFailure(NativeFailure.Api.CF_URL, 0);
            try {
                int status =
                        Native.load("CoreServices", LaunchServices.class)
                                .LSOpenCFURLRef(value, null);
                if (status != 0) throw new NativeFailure(NativeFailure.Api.LAUNCH_SERVICES, status);
            } finally {
                cf.CFRelease(value);
            }
        } else if (os.contains("win")) {
            long result =
                    com.sun.jna.platform.win32.Shell32.INSTANCE
                            .ShellExecute(null, "open", url, null, null, 1)
                            .longValue();
            if (result <= 32) throw new NativeFailure(NativeFailure.Api.SHELL_EXECUTE, result);
        } else {
            PointerByReference error = new PointerByReference();
            boolean ok =
                    Native.load("gio-2.0", BrowserGio.class)
                            .g_app_info_launch_default_for_uri(url, null, error);
            if (error.getValue() != null)
                Native.load("glib-2.0", GLib.class).g_error_free(error.getValue());
            if (!ok) throw new NativeFailure(NativeFailure.Api.GIO_LAUNCH, 0);
        }
    }

    private static String account(String generation) {
        return "mintauth-master-" + UUID.fromString(generation);
    }

    public static final class Windows implements SecretStore {
        private final Path root;

        public Windows(Path root) {
            this.root = root;
        }

        public String name() {
            return "WINDOWS_DPAPI";
        }

        private Path path(String id) {
            return root.resolve(account(id) + ".dpapi");
        }

        public byte[] read(String id) throws Exception {
            Path p = path(id);
            if (Files.isSymbolicLink(p) || !Files.isRegularFile(p) || Files.size(p) > 4096)
                throw new IOException("OS_KEY_MISSING");
            return Crypt32Util.cryptUnprotectData(Files.readAllBytes(p), 1);
        }

        public void write(String id, byte[] value) throws Exception {
            Files.write(
                    path(id),
                    Crypt32Util.cryptProtectData(value, 1),
                    StandardOpenOption.CREATE_NEW);
        }

        public void remove(String id) throws Exception {
            Files.deleteIfExists(path(id));
        }
    }

    interface Security extends Library {
        int SecKeychainFindGenericPassword(
                Pointer keychain,
                int serviceLength,
                byte[] service,
                int accountLength,
                byte[] account,
                IntByReference length,
                PointerByReference data,
                PointerByReference item);

        int SecKeychainAddGenericPassword(
                Pointer keychain,
                int serviceLength,
                byte[] service,
                int accountLength,
                byte[] account,
                int passwordLength,
                byte[] password,
                PointerByReference item);

        int SecKeychainItemFreeContent(Pointer info, Pointer data);

        int SecKeychainItemDelete(Pointer item);
    }

    interface CF extends Library {
        void CFRelease(Pointer value);
    }

    public static final class Mac implements SecretStore {
        private final byte[] service = "online.automint.mintauth".getBytes(StandardCharsets.UTF_8);

        private Security api() {
            return Native.load("Security", Security.class);
        }

        public String name() {
            return "MACOS_KEYCHAIN";
        }

        public byte[] read(String id) throws Exception {
            byte[] user = account(id).getBytes(StandardCharsets.UTF_8);
            IntByReference length = new IntByReference();
            PointerByReference data = new PointerByReference(), item = new PointerByReference();
            Security api = api();
            int code =
                    api.SecKeychainFindGenericPassword(
                            null, service.length, service, user.length, user, length, data, item);
            if (code == -25300) return null;
            if (code != 0) throw new NativeFailure(NativeFailure.Api.KEYCHAIN_READ, code);
            try {
                if (length.getValue() != 32) throw new IOException("OS_KEY_INVALID");
                return data.getValue().getByteArray(0, 32);
            } finally {
                api.SecKeychainItemFreeContent(null, data.getValue());
                if (item.getValue() != null)
                    Native.load("CoreFoundation", CF.class).CFRelease(item.getValue());
            }
        }

        public void write(String id, byte[] value) throws Exception {
            byte[] user = account(id).getBytes(StandardCharsets.UTF_8);
            PointerByReference item = new PointerByReference();
            int code =
                    api().SecKeychainAddGenericPassword(
                                    null,
                                    service.length,
                                    service,
                                    user.length,
                                    user,
                                    value.length,
                                    value,
                                    item);
            if (item.getValue() != null)
                Native.load("CoreFoundation", CF.class).CFRelease(item.getValue());
            if (code != 0) throw new NativeFailure(NativeFailure.Api.KEYCHAIN_WRITE, code);
        }

        public void remove(String id) throws Exception {
            byte[] user = account(id).getBytes(StandardCharsets.UTF_8);
            IntByReference length = new IntByReference();
            PointerByReference data = new PointerByReference(), item = new PointerByReference();
            Security api = api();
            int code =
                    api.SecKeychainFindGenericPassword(
                            null, service.length, service, user.length, user, length, data, item);
            if (code == -25300) return;
            if (code != 0) throw new NativeFailure(NativeFailure.Api.KEYCHAIN_READ, code);
            try {
                if (api.SecKeychainItemDelete(item.getValue()) != 0)
                    throw new IOException("OS_KEYCHAIN_DELETE");
            } finally {
                api.SecKeychainItemFreeContent(null, data.getValue());
                Native.load("CoreFoundation", CF.class).CFRelease(item.getValue());
            }
        }
    }

    @Structure.FieldOrder({"name", "type"})
    public static class Attribute extends Structure {
        public String name;
        public int type;
    }

    @Structure.FieldOrder({
        "name",
        "flags",
        "attributes",
        "reserved",
        "reserved1",
        "reserved2",
        "reserved3",
        "reserved4",
        "reserved5",
        "reserved6",
        "reserved7"
    })
    public static class Schema extends Structure {
        public String name = "online.automint.MintAuth";
        public int flags = 0;
        public Attribute[] attributes = (Attribute[]) new Attribute().toArray(32);
        public int reserved;
        public Pointer reserved1, reserved2, reserved3, reserved4, reserved5, reserved6, reserved7;

        public Schema() {
            attributes[0].name = "installation";
            attributes[0].type = 0;
            write();
        }
    }

    interface Secret extends Library {
        Pointer secret_password_lookup_sync(
                Schema schema, Pointer cancellable, PointerByReference error, Object... attributes);

        boolean secret_password_store_sync(
                Schema schema,
                String collection,
                String label,
                String password,
                Pointer cancellable,
                PointerByReference error,
                Object... attributes);

        boolean secret_password_clear_sync(
                Schema schema, Pointer cancellable, PointerByReference error, Object... attributes);

        void secret_password_free(Pointer password);
    }

    interface GLib extends Library {
        void g_error_free(Pointer error);
    }

    public static final class Linux implements SecretStore {
        public String name() {
            return "LINUX_SECRET_SERVICE";
        }

        private Secret api() {
            return Native.load("secret-1", Secret.class);
        }

        private void check(PointerByReference error) throws IOException {
            if (error.getValue() != null) {
                Native.load("glib-2.0", GLib.class).g_error_free(error.getValue());
                throw new IOException("SECRET_SERVICE_LOCKED");
            }
        }

        public byte[] read(String id) throws Exception {
            Secret api = api();
            PointerByReference error = new PointerByReference();
            Pointer value =
                    api.secret_password_lookup_sync(
                            new Schema(), null, error, "installation", account(id), null);
            check(error);
            if (value == null) return null;
            try {
                return Crypto.unb64(value.getString(0, "UTF-8"));
            } finally {
                api.secret_password_free(value);
            }
        }

        public void write(String id, byte[] value) throws Exception {
            PointerByReference error = new PointerByReference();
            boolean ok =
                    api().secret_password_store_sync(
                                    new Schema(),
                                    "default",
                                    "MintAuth local vault",
                                    Crypto.b64(value),
                                    null,
                                    error,
                                    "installation",
                                    account(id),
                                    null);
            check(error);
            if (!ok) throw new IOException("SECRET_SERVICE_UNAVAILABLE");
        }

        public void remove(String id) throws Exception {
            PointerByReference error = new PointerByReference();
            api().secret_password_clear_sync(
                            new Schema(), null, error, "installation", account(id), null);
            check(error);
        }
    }
}
