// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import static org.junit.Assert.*;

import org.junit.Test;

import java.net.*;
import java.nio.file.*;
import java.util.*;

public class NativeRuntimeTest {
    @Test
    public void isolatedClassesAndNativeResourcesIgnoreAConflictingHost() throws Exception {
        final URL wrong = new URL("file:/synthetic-host-jna-not-for-mintauth");
        ClassLoader hostile =
                new ClassLoader(NativeRuntime.class.getClassLoader()) {
                    @Override
                    protected Class<?> loadClass(String name, boolean resolve)
                            throws ClassNotFoundException {
                        if (name.startsWith("com.sun.jna."))
                            throw new ClassNotFoundException("synthetic legacy JNA API");
                        return super.loadClass(name, resolve);
                    }

                    @Override
                    public URL getResource(String name) {
                        return name.startsWith("com/sun/jna/") ? wrong : super.getResource(name);
                    }

                    @Override
                    public Enumeration<URL> getResources(String name) throws java.io.IOException {
                        return name.startsWith("com/sun/jna/")
                                ? Collections.enumeration(Collections.singletonList(wrong))
                                : super.getResources(name);
                    }
                };
        try (NativeRuntime.Loader isolated =
                new NativeRuntime.Loader(NativeRuntime.sources(), hostile)) {
            Class<?> nativeType = Class.forName("com.sun.jna.Native", true, isolated);
            assertSame(isolated, nativeType.getClassLoader());
            nativeType.getMethod("load", String.class, Class.class);
            assertEquals(8, nativeType.getField("POINTER_SIZE").getInt(null));
            Class<?> memoryType = Class.forName("com.sun.jna.Memory", true, isolated);
            Object memory = memoryType.getConstructor(long.class).newInstance(8L);
            memoryType.getMethod("setLong", long.class, long.class).invoke(memory, 0L, 123456789L);
            assertEquals(
                    123456789L, memoryType.getMethod("getLong", long.class).invoke(memory, 0L));
            for (String path :
                    Arrays.asList(
                            "com/sun/jna/darwin-aarch64/libjnidispatch.jnilib",
                            "com/sun/jna/darwin-x86-64/libjnidispatch.jnilib")) {
                assertNotNull(isolated.getResource(path));
                assertNotEquals(wrong, isolated.getResource(path));
                List<URL> resources = Collections.list(isolated.getResources(path));
                assertFalse(resources.contains(wrong));
                assertFalse(resources.isEmpty());
            }
            assertSame(
                    SecretStore.class, Class.forName(SecretStore.class.getName(), false, isolated));
            Class<?> factory = Class.forName(NativeStores.class.getName(), true, isolated);
            assertSame(isolated, factory.getClassLoader());
            assertTrue(NativeRuntime.owns(factory));
            SecretStore store =
                    (SecretStore)
                            factory.getMethod("forPlatform", Path.class)
                                    .invoke(
                                            null,
                                            Files.createTempDirectory("mintauth-isolated-store"));
            assertEquals(NativeStores.forPlatform(Paths.get(".")).name(), store.name());
            assertSame(
                    isolated,
                    Class.forName(HardwareKeys.class.getName(), false, isolated).getClassLoader());
        }
    }

    @Test
    public void missingBundledJnaNeverFallsBackToTheHostCopy() throws Exception {
        try (NativeRuntime.Loader empty =
                new NativeRuntime.Loader(new URL[0], NativeRuntime.class.getClassLoader())) {
            try {
                empty.loadClass("com.sun.jna.Native");
                fail("Host JNA must not be used");
            } catch (ClassNotFoundException expected) {
            }
            assertNull(empty.getResource("com/sun/jna/Native.class"));
        }
    }

    @Test
    public void launchWrapperClassEntryCodeSourceResolvesToTheLocalJar() throws Exception {
        Path jar = Files.createTempFile("MintAuth spaces café-", ".jar");
        try (java.util.jar.JarOutputStream out =
                new java.util.jar.JarOutputStream(Files.newOutputStream(jar))) {}
        URL archive = jar.toUri().toURL();
        URL entry =
                new URL("jar:" + archive + "!/online/automint/mintauth/core/NativeRuntime.class");
        assertEquals(jar, NativeRuntime.localSource(entry));
        assertEquals(jar, NativeRuntime.localSource(archive));
        ClassLoader legacy =
                new ClassLoader(NativeRuntime.class.getClassLoader()) {
                    @Override
                    protected Class<?> loadClass(String name, boolean resolve)
                            throws ClassNotFoundException {
                        if (!name.equals(NativeRuntime.class.getName()))
                            return super.loadClass(name, resolve);
                        synchronized (getClassLoadingLock(name)) {
                            Class<?> type = findLoadedClass(name);
                            if (type == null) {
                                try (java.io.InputStream input =
                                        getParent()
                                                .getResourceAsStream(
                                                        name.replace('.', '/') + ".class")) {
                                    java.io.ByteArrayOutputStream bytes =
                                            new java.io.ByteArrayOutputStream();
                                    byte[] buffer = new byte[4096];
                                    int count;
                                    while ((count = input.read(buffer)) != -1)
                                        bytes.write(buffer, 0, count);
                                    byte[] code = bytes.toByteArray();
                                    type =
                                            defineClass(
                                                    name,
                                                    code,
                                                    0,
                                                    code.length,
                                                    new java.security.ProtectionDomain(
                                                            new java.security.CodeSource(
                                                                    entry,
                                                                    (java.security.cert.Certificate
                                                                                    [])
                                                                            null),
                                                            null));
                                } catch (java.io.IOException error) {
                                    throw new ClassNotFoundException(name, error);
                                }
                            }
                            if (resolve) resolveClass(type);
                            return type;
                        }
                    }
                };
        Class<?> resolver = Class.forName(NativeRuntime.class.getName(), true, legacy);
        java.lang.reflect.Method sources = resolver.getDeclaredMethod("sources");
        sources.setAccessible(true);
        assertArrayEquals(new URL[] {archive}, (URL[]) sources.invoke(null));
    }

    @Test
    public void nativeSourceRejectsRemoteArchivesAndMissingSourcesWithoutDownloading()
            throws Exception {
        for (URL location :
                Arrays.asList(
                        null,
                        new URL("https://example.invalid/native.jar"),
                        new URL("jar:https://example.invalid/native.jar!/NativeRuntime.class"),
                        new URL("file:/mintauth-nonexistent-native-source.jar"))) {
            try {
                NativeRuntime.localSource(location);
                fail("Only an existing local source is allowed");
            } catch (java.io.IOException expected) {
                assertEquals("NATIVE_RUNTIME_SOURCE", expected.getMessage());
            }
        }
    }

    @Test
    public void loaderConstructorItselfRejectsRemoteSources() throws Exception {
        for (URL source : Arrays.asList(new URL("https://example.invalid/native.jar"),
                new URL("jar:https://example.invalid/native.jar!/Native.class"))) {
            try (NativeRuntime.Loader ignored = new NativeRuntime.Loader(new URL[] {source},
                    NativeRuntime.class.getClassLoader())) {
                fail("Remote sources must be rejected before class/resource loading");
            } catch (java.io.IOException expected) {
                assertEquals("NATIVE_RUNTIME_SOURCE", expected.getMessage());
            }
        }
    }

    @Test
    public void darwinIsNotMisclassifiedAsWindows() {
        assertEquals("MACOS_ARM64", RuntimePlatform.identifier("Darwin", "aarch64"));
        assertEquals("MACOS_X64", RuntimePlatform.identifier("Darwin", "x86_64"));
    }
}
