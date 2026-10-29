// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.net.*;
import java.nio.file.*;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.jar.JarFile;

public final class NativeRuntime {
    private static final String JNA_VERSION = "5.18.1";
    private static volatile Loader runtime;

    private NativeRuntime() {}

    static String state() {
        return runtime == null ? "NOT_LOADED" : "ISOLATED_JNA_5_18_1";
    }

    public static boolean owns(Class<?> type) {
        return type.getClassLoader() instanceof Loader;
    }

    static final class Loader extends URLClassLoader {
        Loader(URL[] sources, ClassLoader parent) throws IOException {
            super(checkedSources(sources), parent);
        }

        private static URL[] checkedSources(URL[] sources) throws IOException {
            URL[] checked = new URL[sources.length];
            for (int i = 0; i < sources.length; i++) {
                try { checked[i] = localSource(sources[i]).toUri().toURL(); }
                catch (IOException error) { throw error; }
                catch (Exception error) { throw new IOException("NATIVE_RUNTIME_SOURCE", error); }
            }
            return checked;
        }

        private boolean nativeClass(String name) {
            return name.startsWith("com.sun.jna.")
                    || name.equals(NativeStores.class.getName())
                    || name.startsWith(NativeStores.class.getName() + "$")
                    || name.equals(HardwareKeys.class.getName())
                    || name.startsWith(HardwareKeys.class.getName() + "$");
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            if (!nativeClass(name)) return super.loadClass(name, resolve);
            synchronized (getClassLoadingLock(name)) {
                Class<?> loaded = findLoadedClass(name);
                if (loaded == null) loaded = findClass(name);
                if (resolve) resolveClass(loaded);
                return loaded;
            }
        }

        @Override
        public URL getResource(String name) {
            return name.startsWith("com/sun/jna/") ? findResource(name) : super.getResource(name);
        }

        @Override
        public Enumeration<URL> getResources(String name) throws IOException {
            return name.startsWith("com/sun/jna/") ? findResources(name) : super.getResources(name);
        }
    }

    static Path localSource(URL location) throws Exception {
        if (location == null) throw new IOException("NATIVE_RUNTIME_SOURCE");
        URL local = location;
        if ("jar".equals(local.getProtocol())) {
            JarURLConnection connection = (JarURLConnection) local.openConnection();
            connection.setUseCaches(false);
            local = connection.getJarFileURL();
        }
        if (!"file".equals(local.getProtocol())) throw new IOException("NATIVE_RUNTIME_SOURCE");
        Path source = Paths.get(local.toURI());
        if (Files.isSymbolicLink(source)
                || (!Files.isRegularFile(source) && !Files.isDirectory(source)))
            throw new IOException("NATIVE_RUNTIME_SOURCE");
        return source;
    }

    static URL[] sources() throws Exception {
        java.security.CodeSource codeSource =
                NativeRuntime.class.getProtectionDomain().getCodeSource();
        Path source = localSource(codeSource == null ? null : codeSource.getLocation());
        URL own = source.toUri().toURL();
        List<URL> result = new ArrayList<>();
        result.add(own);
        if (Files.isDirectory(source)) {
            for (String resource :
                    Arrays.asList(
                            "com/sun/jna/Native.class",
                            "com/sun/jna/platform/win32/Crypt32Util.class")) {
                Enumeration<URL> candidates =
                        NativeRuntime.class.getClassLoader().getResources(resource);
                boolean found = false;
                while (candidates.hasMoreElements()) {
                    URL candidate = candidates.nextElement();
                    if (!"jar".equals(candidate.getProtocol())) continue;
                    JarURLConnection connection = (JarURLConnection) candidate.openConnection();
                    connection.setUseCaches(false);
                    try (JarFile jar = connection.getJarFile()) {
                        String version =
                                jar.getManifest() == null
                                        ? null
                                        : jar.getManifest()
                                                .getMainAttributes()
                                                .getValue("Implementation-Version");
                        if (version != null
                                && (version.equals(JNA_VERSION)
                                        || version.startsWith(JNA_VERSION + " "))
                                && "file".equals(connection.getJarFileURL().getProtocol())) {
                            result.add(connection.getJarFileURL());
                            found = true;
                            break;
                        }
                    }
                }
                if (!found) throw new IOException("NATIVE_RUNTIME_DEPENDENCY");
            }
        } else if (!Files.isRegularFile(source)) throw new IOException("NATIVE_RUNTIME_SOURCE");
        return result.toArray(new URL[0]);
    }

    private static synchronized Loader loader() throws Exception {
        if (runtime != null) return runtime;
        Loader candidate = new Loader(sources(), NativeRuntime.class.getClassLoader());
        try {
            Class<?> nativeType = Class.forName("com.sun.jna.Native", true, candidate);
            java.lang.reflect.Field version = nativeType.getField("VERSION");
            version.setAccessible(true);
            if (!JNA_VERSION.equals(version.get(null))
                    || nativeType.getField("POINTER_SIZE").getInt(null) != 8)
                throw new IOException("NATIVE_RUNTIME_VERSION");
            runtime = candidate;
            return candidate;
        } catch (Throwable error) {
            candidate.close();
            throw safe(error);
        }
    }

    private static Exception safe(Throwable error) {
        if (error instanceof InvocationTargetException)
            error = ((InvocationTargetException) error).getCause();
        if (error instanceof VirtualMachineError) throw (VirtualMachineError) error;
        if (error instanceof ThreadDeath) throw (ThreadDeath) error;
        return error instanceof Exception
                ? (Exception) error
                : new IOException("NATIVE_RUNTIME_UNAVAILABLE", error);
    }

    private static Object invoke(Class<?> owner, String method, Class<?> parameter, Object argument)
            throws Exception {
        try {
            Class<?> isolated = Class.forName(owner.getName(), true, loader());
            return isolated.getMethod(method, parameter).invoke(null, argument);
        } catch (Throwable error) {
            throw safe(error);
        }
    }

    static SecretStore store(final Path root) {
        return new SecretStore() {
            private SecretStore delegate;

            public String name() {
                String os = System.getProperty("os.name").toLowerCase(Locale.ROOT);
                return os.contains("mac") || os.contains("darwin")
                        ? "MACOS_KEYCHAIN"
                        : os.contains("win") ? "WINDOWS_DPAPI" : "LINUX_SECRET_SERVICE";
            }

            private synchronized SecretStore backend() throws Exception {
                if (delegate == null)
                    delegate =
                            (SecretStore)
                                    invoke(NativeStores.class, "forPlatform", Path.class, root);
                return delegate;
            }

            public byte[] read(String generation) throws Exception {
                try {
                    return backend().read(generation);
                } catch (LinkageError error) {
                    throw new IOException("NATIVE_RUNTIME_UNAVAILABLE", error);
                }
            }

            public void write(String generation, byte[] secret) throws Exception {
                try {
                    backend().write(generation, secret);
                } catch (LinkageError error) {
                    throw new IOException("NATIVE_RUNTIME_UNAVAILABLE", error);
                }
            }

            public void remove(String generation) throws Exception {
                try {
                    backend().remove(generation);
                } catch (LinkageError error) {
                    throw new IOException("NATIVE_RUNTIME_UNAVAILABLE", error);
                }
            }
        };
    }

    static String windowsDataRoot() throws Exception {
        try {
            Class<?> isolated = Class.forName(NativeStores.class.getName(), true, loader());
            return (String) isolated.getMethod("windowsDataRoot").invoke(null);
        } catch (Throwable error) {
            throw safe(error);
        }
    }

    static void openWebsite(String url) throws Exception {
        invoke(NativeStores.class, "openWebsite", String.class, url);
    }

    static Crypto.Signer createKey(String generation) {
        try {
            return (Crypto.Signer) invoke(HardwareKeys.class, "create", String.class, generation);
        } catch (Exception | LinkageError unavailable) {
            return null;
        }
    }

    static Crypto.Signer openKey(String reference) throws GeneralSecurityException {
        try {
            return (Crypto.Signer) invoke(HardwareKeys.class, "open", String.class, reference);
        } catch (Exception | LinkageError error) {
            throw new GeneralSecurityException("ENROLLED_KEY_UNAVAILABLE", error);
        }
    }

    static void removeKey(String reference) throws Exception {
        invoke(HardwareKeys.class, "remove", String.class, reference);
    }
}
