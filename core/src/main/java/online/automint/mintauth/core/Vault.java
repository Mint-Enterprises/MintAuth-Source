// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import com.google.gson.JsonObject;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

public final class Vault implements AutoCloseable {
    private static final ConcurrentHashMap<Path, ReentrantLock> PROCESS_LOCKS =
            new ConcurrentHashMap<>();

    public interface Transaction<T> {
        T run(JsonObject value) throws Exception;
    }

    public static final class Locked extends IOException {
        public Locked(String reason) {
            super(reason);
        }
    }

    private final Path root;
    private volatile FlowDiagnostics trace = FlowDiagnostics.silent();

    void setDiagnostics(FlowDiagnostics value) {
        trace = value;
    }

    private final SecretStore store;
    private byte[] key;
    private byte[] passwordWrappingKey;
    private String unlockedGeneration;
    private volatile boolean cleanupPartial;

    public Vault(Path root, SecretStore store) throws IOException {
        this.root = root.toAbsolutePath().normalize();
        this.store = store;
        secureDirectory(this.root);
    }

    public static Path defaultRoot() {
        String os = System.getProperty("os.name").toLowerCase(Locale.ROOT),
                home = System.getProperty("user.home");
        if (os.contains("win") && !os.contains("darwin")) {
            String app = System.getenv("LOCALAPPDATA");
            try {
                app = NativeStores.windowsDataRoot();
            } catch (Exception | LinkageError unavailable) {
            }
            return Paths.get(app != null ? app : home, "MintAuth");
        }
        if (os.contains("mac") || os.contains("darwin"))
            return Paths.get(home, "Library", "Application Support", "MintAuth");
        String xdg = System.getenv("XDG_DATA_HOME");
        return Paths.get(
                xdg != null && !xdg.isEmpty() ? xdg : Paths.get(home, ".local", "share").toString(),
                "mintauth");
    }

    private static void secureDirectory(Path path) throws IOException {
        Files.createDirectories(path);
        if (Files.isSymbolicLink(path)) throw new IOException("VAULT_SYMLINK");
        secure(path, true);
    }

    private static void secure(Path path, boolean directory) throws IOException {
        PosixFileAttributeView posix =
                Files.getFileAttributeView(
                        path, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (posix != null) {
            Files.setPosixFilePermissions(
                    path, PosixFilePermissions.fromString(directory ? "rwx------" : "rw-------"));
            return;
        }
        AclFileAttributeView acl =
                Files.getFileAttributeView(
                        path, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (acl != null) {
            UserPrincipal owner = Files.getOwner(path, LinkOption.NOFOLLOW_LINKS);
            acl.setAcl(
                    Collections.singletonList(
                            AclEntry.newBuilder()
                                    .setType(AclEntryType.ALLOW)
                                    .setPrincipal(owner)
                                    .setPermissions(EnumSet.allOf(AclEntryPermission.class))
                                    .build()));
        }
    }

    private Path path(String name) throws IOException {
        Path p = root.resolve(name).normalize();
        if (!p.getParent().equals(root) || Files.isSymbolicLink(p))
            throw new IOException("VAULT_PATH");
        return p;
    }

    private void atomic(String name, byte[] bytes) throws IOException {
        trace.step(FlowDiagnostics.Step.VAULT_COMMIT, FlowDiagnostics.Result.STARTED);
        try {
            atomicInternal(name, bytes);
            trace.step(FlowDiagnostics.Step.VAULT_COMMIT, FlowDiagnostics.Result.SUCCEEDED);
        } catch (IOException | RuntimeException | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.VAULT_COMMIT, error);
            throw error;
        }
    }

    private void atomicInternal(String name, byte[] bytes) throws IOException {
        Path target = path(name), tmp = path("tmp-" + UUID.randomUUID());
        try (FileChannel ch =
                FileChannel.open(tmp, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            secure(tmp, false);
            ByteBuffer b = ByteBuffer.wrap(bytes);
            while (b.hasRemaining()) ch.write(b);
            ch.force(true);
        }
        try {
            Files.move(
                    tmp,
                    target,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    private JsonObject headerUnlocked() throws IOException {
        Path file = path("header.json");
        BasicFileAttributes attributes;
        try {
            attributes =
                    Files.readAttributes(
                            file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        } catch (NoSuchFileException absent) {
            return null;
        }
        if (!attributes.isRegularFile() || attributes.size() > 16384)
            throw new IOException("VAULT_HEADER_LIMIT");
        JsonObject header =
                Json.object(new String(Files.readAllBytes(file), StandardCharsets.UTF_8), 16384);
        if (header.get("version").getAsInt() != 1) throw new IOException("VAULT_VERSION");
        UUID.fromString(Json.string(header, "generation"));
        return header;
    }

    public synchronized JsonObject header() throws Exception {
        return locked(
                () -> {
                    recoverRekey();
                    JsonObject h = headerUnlocked();
                    return h == null ? null : h.deepCopy();
                });
    }

    public interface LockedOperation<T> {
        T run() throws Exception;
    }

    public synchronized <T> T locked(LockedOperation<T> action) throws Exception {
        ReentrantLock processLock =
                PROCESS_LOCKS.computeIfAbsent(root, ignored -> new ReentrantLock());
        processLock.lockInterruptibly();
        try {
            Path lockPath = path("vault.lock");
            try (FileChannel channel =
                    FileChannel.open(
                            lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
                secure(lockPath, false);
                try (FileLock ignored = channel.lock()) {
                    return action.run();
                }
            }
        } finally {
            processLock.unlock();
        }
    }

    public synchronized void unlock(final char[] password, final boolean passwordFallback)
            throws Exception {
        trace.step(FlowDiagnostics.Step.VAULT_UNLOCK, FlowDiagnostics.Result.STARTED);
        try {
            unlockInternal(password, passwordFallback);
            trace.step(FlowDiagnostics.Step.VAULT_UNLOCK, FlowDiagnostics.Result.SUCCEEDED);
        } catch (Exception | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.VAULT_UNLOCK, error);
            throw error;
        }
    }

    private synchronized void unlockInternal(final char[] password, final boolean passwordFallback)
            throws Exception {
        locked(
                () -> {
                    recoverRekey();
                    JsonObject h = headerUnlocked();
                    boolean creating = h == null;
                    if (creating) {
                        h = new JsonObject();
                        h.addProperty("version", 1);
                        h.addProperty("generation", UUID.randomUUID().toString());
                        h.addProperty(
                                "backend",
                                passwordFallback
                                        ? "PASSWORD"
                                        : store == null ? "UNAVAILABLE" : store.name());
                        h.addProperty("salt", Crypto.b64(Crypto.random(16)));
                        h.addProperty("cleanupLocator", Crypto.b64(Crypto.random(32)));
                        h.addProperty("cleanupReceipt", Crypto.b64(Crypto.random(32)));
                    }
                    String generation = Json.string(h, "generation"),
                            backend = Json.string(h, "backend");
                    if (Files.exists(path("wiped-" + generation)))
                        throw new Locked("VAULT_REVOKED");
                    byte[] next;
                    if (backend.equals("PASSWORD")) {
                        if (password == null) throw new Locked("PASSWORD_REQUIRED");
                        byte[] wrapping =
                                Crypto.passwordKey(password, Crypto.unb64(Json.string(h, "salt")));
                        try {
                            next =
                                    h.has("wrappedMasterKey")
                                            ? Crypto.decrypt(
                                                    wrapping,
                                                    Crypto.unb64(
                                                            Json.string(h, "wrappedMasterKey")),
                                                    "mintauth:wrap:v1:" + generation)
                                            : wrapping.clone();
                            if (passwordWrappingKey != null)
                                Arrays.fill(passwordWrappingKey, (byte) 0);
                            passwordWrappingKey = wrapping.clone();
                        } finally {
                            Arrays.fill(wrapping, (byte) 0);
                        }
                    } else {
                        if (store == null || !backend.equals(store.name()))
                            throw new Locked("OS_STORE_UNAVAILABLE");
                        next = null;
                        try {
                            next = creating ? Crypto.random(32) : store.read(generation);
                            if (next == null || next.length != 32)
                                throw new Locked("OS_KEY_MISSING");
                            if (creating) store.write(generation, next);
                        } catch (Locked locked) {
                            throw locked;
                        } catch (Exception | LinkageError error) {
                            if (next != null) Arrays.fill(next, (byte) 0);
                            Locked unavailable = new Locked("OS_STORE_UNAVAILABLE");
                            unavailable.initCause(error);
                            throw unavailable;
                        }
                    }
                    byte[] previous = key;
                    key = next;
                    unlockedGeneration = generation;
                    try {
                        if (creating) {
                            save(new JsonObject(), generation);
                            atomic(
                                    "header.json",
                                    Json.GSON.toJson(h).getBytes(StandardCharsets.UTF_8));
                        } else load(generation);
                    } catch (Exception e) {
                        Arrays.fill(next, (byte) 0);
                        key = null;
                        unlockedGeneration = null;
                        throw new Locked("VAULT_LOCKED_OR_CORRUPT");
                    } finally {
                        if (previous != null) Arrays.fill(previous, (byte) 0);
                    }
                    return null;
                });
    }

    private JsonObject load(String generation) throws Exception {
        if (key == null || !generation.equals(unlockedGeneration)) throw new Locked("VAULT_LOCKED");
        Path file = path("vault-" + generation + ".enc");
        if (!Files.exists(file) || Files.size(file) > 4 * 1024 * 1024)
            throw new Locked("VAULT_MISSING_OR_CORRUPT");
        byte[] plain =
                Crypto.decrypt(key, Files.readAllBytes(file), "mintauth:local:v1:" + generation);
        try {
            return Json.object(new String(plain, StandardCharsets.UTF_8), 4 * 1024 * 1024);
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
    }

    private void save(JsonObject data, String generation) throws Exception {
        trace.step(FlowDiagnostics.Step.VAULT_ENCRYPT, FlowDiagnostics.Result.STARTED);
        try {
            saveInternal(data, generation);
            trace.step(FlowDiagnostics.Step.VAULT_ENCRYPT, FlowDiagnostics.Result.SUCCEEDED);
        } catch (Exception | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.VAULT_ENCRYPT, error);
            throw error;
        }
    }

    private void saveInternal(JsonObject data, String generation) throws Exception {
        byte[] plain = Json.GSON.toJson(data).getBytes(StandardCharsets.UTF_8);
        try {
            if (plain.length > 4 * 1024 * 1024 - 32) throw new IOException("VAULT_LIMIT");
            atomic(
                    "vault-" + generation + ".enc",
                    Crypto.encrypt(key, plain, "mintauth:local:v1:" + generation));
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
    }

    synchronized <T> T inspect(Transaction<T> action) throws Exception {
        return locked(
                () -> {
                    recoverRekey();
                    JsonObject header = headerUnlocked();
                    if (header == null) throw new Locked("VAULT_UNINITIALIZED");
                    String generation = Json.string(header, "generation");
                    if (Files.exists(path("wiped-" + generation)))
                        throw new Locked("VAULT_REVOKED");
                    return action.run(load(generation));
                });
    }

    public synchronized <T> T update(final Transaction<T> action) throws Exception {
        trace.step(FlowDiagnostics.Step.VAULT_TRANSACTION, FlowDiagnostics.Result.STARTED);
        try {
            T result = updateInternal(action);
            trace.step(FlowDiagnostics.Step.VAULT_TRANSACTION, FlowDiagnostics.Result.SUCCEEDED);
            return result;
        } catch (Exception | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.VAULT_TRANSACTION, error);
            throw error;
        }
    }

    private synchronized <T> T updateInternal(final Transaction<T> action) throws Exception {
        return locked(
                () -> {
                    JsonObject h = headerUnlocked();
                    if (h == null) throw new Locked("VAULT_UNINITIALIZED");
                    String generation = Json.string(h, "generation");
                    if (Files.exists(path("wiped-" + generation)))
                        throw new Locked("VAULT_REVOKED");
                    JsonObject data = load(generation);
                    T result = action.run(data);
                    if (Files.exists(path("wiped-" + generation)))
                        throw new Locked("VAULT_REVOKED");
                    if (data.has("deviceKey")) {
                        String reference =
                                Json.string(data.getAsJsonObject("deviceKey"), "reference");
                        if (!Objects.equals(reference, Json.optional(h, "keyReference")))
                            persistReference(h, reference);
                    }
                    save(data, generation);
                    return result;
                });
    }

    public synchronized JsonObject read() throws Exception {
        try {
            JsonObject result = readInternal();
            trace.state(FlowDiagnostics.Step.VAULT_READ, FlowDiagnostics.Result.SUCCEEDED);
            return result;
        } catch (Exception | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.VAULT_READ, error);
            throw error;
        }
    }

    private synchronized JsonObject readInternal() throws Exception {
        return locked(
                () -> {
                    recoverRekey();
                    JsonObject header = headerUnlocked();
                    if (header == null) throw new Locked("VAULT_UNINITIALIZED");
                    String generation = Json.string(header, "generation");
                    if (Files.exists(path("wiped-" + generation)))
                        throw new Locked("VAULT_REVOKED");
                    return load(generation).deepCopy();
                });
    }

    public synchronized void bind(final String deviceId, final String generation) throws Exception {
        UUID.fromString(deviceId);
        UUID.fromString(generation);
        locked(
                () -> {
                    JsonObject h = headerUnlocked();
                    if (h == null
                            || !generation.equals(Json.string(h, "generation"))
                            || Files.exists(path("wiped-" + generation)))
                        throw new Locked("VAULT_REVOKED");
                    h.addProperty("deviceId", deviceId);
                    atomic("header.json", Json.GSON.toJson(h).getBytes(StandardCharsets.UTF_8));
                    return null;
                });
    }

    private void persistReference(JsonObject header, String reference) throws Exception {
        String generation = Json.string(header, "generation");
        if (!reference.equals("SOFTWARE")
                && !reference.equals("CNG_TPM:" + generation)
                && !reference.equals("SECURE_ENCLAVE:" + generation))
            throw new IOException("KEY_REFERENCE");
        if (Files.exists(path("wiped-" + generation))) throw new Locked("VAULT_REVOKED");
        header.addProperty("keyReference", reference);
        atomic("header.json", Json.GSON.toJson(header).getBytes(StandardCharsets.UTF_8));
    }

    public boolean cleanupPartial() {
        return cleanupPartial;
    }

    private boolean matches(JsonObject header, JsonObject command) {
        return header != null
                && Objects.equals(
                        Json.optional(header, "deviceId"), Json.optional(command, "deviceId"))
                && Json.string(header, "generation")
                        .equals(Json.string(command, "vaultGeneration"));
    }

    private void removeKeys(JsonObject header) {
        String generation = Json.string(header, "generation");
        if (store != null && store.name().equals(Json.string(header, "backend")))
            try {
                store.remove(generation);
            } catch (Exception ignored) {
                cleanupPartial = true;
            }
        String reference = Json.optional(header, "keyReference");
        if (reference != null && !reference.equals("SOFTWARE")) {
            if (!reference.equals("CNG_TPM:" + generation)
                    && !reference.equals("SECURE_ENCLAVE:" + generation)) {
                cleanupPartial = true;
                return;
            }
            try {
                HardwareKeys.remove(reference);
            } catch (Exception | LinkageError error) {
                trace.failure(FlowDiagnostics.Step.VAULT_NATIVE_CLEANUP, error);
                cleanupPartial = true;
            }
        }
    }

    public synchronized boolean clear(final JsonObject verifiedCommand) throws Exception {
        trace.step(FlowDiagnostics.Step.VAULT_WIPE, FlowDiagnostics.Result.STARTED);
        try {
            boolean result = clearInternal(verifiedCommand);
            trace.step(
                    FlowDiagnostics.Step.VAULT_WIPE,
                    result ? FlowDiagnostics.Result.SUCCEEDED : FlowDiagnostics.Result.SKIPPED);
            return result;
        } catch (Exception | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.VAULT_WIPE, error);
            throw error;
        }
    }

    private synchronized boolean clearInternal(final JsonObject verifiedCommand) throws Exception {
        return locked(
                () -> {
                    JsonObject h = headerUnlocked();
                    if (h == null) return false;
                    String generation = Json.string(h, "generation");
                    JsonObject target =
                            matches(h, verifiedCommand)
                                    ? h
                                    : h.has("previousEnrollment")
                                                    && matches(
                                                            h.getAsJsonObject("previousEnrollment"),
                                                            verifiedCommand)
                                            ? h.getAsJsonObject("previousEnrollment")
                                            : null;
                    if (target == null) return false;
                    String targetGeneration = Json.string(target, "generation");
                    UUID.fromString(targetGeneration);
                    cleanupPartial = false;
                    atomic(
                            "wiped-" + targetGeneration,
                            Json.GSON.toJson(verifiedCommand).getBytes(StandardCharsets.UTF_8));
                    Files.deleteIfExists(path("vault-" + targetGeneration + ".enc"));
                    removeKeys(target);
                    if (targetGeneration.equals(generation) || !h.has("deviceId")) {
                        if (!targetGeneration.equals(generation)) {
                            JsonObject delegated = verifiedCommand.deepCopy();
                            delegated.addProperty("vaultGeneration", generation);
                            delegated.addProperty("parentGeneration", targetGeneration);
                            atomic(
                                    "wiped-" + generation,
                                    Json.GSON.toJson(delegated).getBytes(StandardCharsets.UTF_8));
                            Files.deleteIfExists(path("vault-" + generation + ".enc"));
                            removeKeys(h);
                        }
                        close();
                    }
                    return true;
                });
    }

    private void recoverRekey() throws Exception {
        Path staging = path("next-header.json");
        if (!Files.exists(staging)) return;
        trace.step(FlowDiagnostics.Step.VAULT_JOURNAL, FlowDiagnostics.Result.EXISTING);
        if (Files.size(staging) > 16384) throw new IOException("VAULT_HEADER_LIMIT");
        JsonObject
                next =
                        Json.object(
                                new String(Files.readAllBytes(staging), StandardCharsets.UTF_8),
                                16384),
                old = headerUnlocked();
        String nextGeneration = Json.string(next, "generation");
        UUID.fromString(nextGeneration);
        if (old != null && nextGeneration.equals(Json.string(old, "generation"))) {
            if (next.has("previousEnrollment")) {
                JsonObject parent = next.getAsJsonObject("previousEnrollment");
                String previous = Json.string(parent, "generation");
                UUID.fromString(previous);
                Files.deleteIfExists(path("vault-" + previous + ".enc"));
                removeKeys(parent);
            }
            Files.deleteIfExists(staging);
            return;
        }
        if (old != null
                && next.has("previousEnrollment")
                && Json.string(old, "generation")
                        .equals(
                                Json.string(
                                        next.getAsJsonObject("previousEnrollment"),
                                        "generation"))) {
            Path marker = path("wiped-" + Json.string(old, "generation"));
            if (Files.exists(marker) && Files.exists(path("vault-" + nextGeneration + ".enc"))) {
                JsonObject reason =
                        Json.object(
                                new String(Files.readAllBytes(marker), StandardCharsets.UTF_8),
                                16384);
                if ("LOCAL_RELINK".equals(Json.optional(reason, "action"))) {
                    atomic("header.json", Json.GSON.toJson(next).getBytes(StandardCharsets.UTF_8));
                    Files.deleteIfExists(path("vault-" + Json.string(old, "generation") + ".enc"));
                    removeKeys(old);
                    Files.deleteIfExists(staging);
                    return;
                }
            }
        }
        Files.deleteIfExists(path("vault-" + nextGeneration + ".enc"));
        removeKeys(next);
        Files.deleteIfExists(staging);
    }

    public synchronized void beginRelink() throws Exception {
        trace.step(FlowDiagnostics.Step.VAULT_RELINK, FlowDiagnostics.Result.STARTED);
        try {
            beginRelinkInternal();
            trace.step(FlowDiagnostics.Step.VAULT_RELINK, FlowDiagnostics.Result.SUCCEEDED);
        } catch (Exception | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.VAULT_RELINK, error);
            throw error;
        }
    }

    private synchronized void beginRelinkInternal() throws Exception {
        locked(
                () -> {
                    JsonObject old = headerUnlocked();
                    if (old == null || !old.has("deviceId")) return null;
                    String oldGeneration = Json.string(old, "generation");
                    if (Files.exists(path("wiped-" + oldGeneration)))
                        throw new Locked("VAULT_REVOKED");
                    JsonObject previous = load(oldGeneration);
                    if (previous.has("authorization")) throw new IOException("UNLINK_FIRST");
                    JsonObject locals = new JsonObject();
                    if (previous.has("accounts"))
                        for (Map.Entry<String, com.google.gson.JsonElement> entry :
                                previous.getAsJsonObject("accounts").entrySet())
                            if ("LOCAL"
                                    .equals(
                                            Json.optional(
                                                    entry.getValue().getAsJsonObject(), "source")))
                                locals.add(entry.getKey(), entry.getValue().deepCopy());
                    JsonObject next = new JsonObject();
                    String generation = UUID.randomUUID().toString(),
                            backend = Json.string(old, "backend");
                    next.addProperty("version", 1);
                    next.addProperty("generation", generation);
                    next.addProperty("backend", backend);
                    next.addProperty("salt", Json.string(old, "salt"));
                    next.addProperty("cleanupLocator", Crypto.b64(Crypto.random(32)));
                    next.addProperty("cleanupReceipt", Crypto.b64(Crypto.random(32)));
                    JsonObject parent = new JsonObject();
                    for (String field :
                            Arrays.asList(
                                    "generation",
                                    "backend",
                                    "deviceId",
                                    "cleanupLocator",
                                    "cleanupReceipt",
                                    "keyReference"))
                        if (old.has(field)) parent.add(field, old.get(field));
                    next.add("previousEnrollment", parent);
                    byte[] newKey = Crypto.random(32),
                            wrapping =
                                    passwordWrappingKey == null
                                            ? null
                                            : passwordWrappingKey.clone();
                    try {
                        if (backend.equals("PASSWORD")) {
                            if (wrapping == null) throw new Locked("PASSWORD_REQUIRED");
                            next.addProperty(
                                    "wrappedMasterKey",
                                    Crypto.b64(
                                            Crypto.encrypt(
                                                    wrapping,
                                                    newKey,
                                                    "mintauth:wrap:v1:" + generation)));
                        } else {
                            if (store == null || !store.name().equals(backend))
                                throw new Locked("OS_STORE_UNAVAILABLE");
                            store.write(generation, newKey);
                        }
                        JsonObject seed = new JsonObject();
                        seed.add("pendingLocalAccounts", locals);
                        byte[] plain = Json.GSON.toJson(seed).getBytes(StandardCharsets.UTF_8);
                        try {
                            atomic(
                                    "vault-" + generation + ".enc",
                                    Crypto.encrypt(
                                            newKey, plain, "mintauth:local:v1:" + generation));
                        } finally {
                            Arrays.fill(plain, (byte) 0);
                        }
                        atomic(
                                "next-header.json",
                                Json.GSON.toJson(next).getBytes(StandardCharsets.UTF_8));
                        JsonObject marker = Json.obj("action", "LOCAL_RELINK");
                        marker.addProperty("vaultGeneration", oldGeneration);
                        atomic(
                                "wiped-" + oldGeneration,
                                Json.GSON.toJson(marker).getBytes(StandardCharsets.UTF_8));
                        atomic(
                                "header.json",
                                Json.GSON.toJson(next).getBytes(StandardCharsets.UTF_8));
                        Files.deleteIfExists(path("vault-" + oldGeneration + ".enc"));
                        removeKeys(old);
                        Files.deleteIfExists(path("next-header.json"));
                        close();
                        key = newKey.clone();
                        unlockedGeneration = generation;
                        if (wrapping != null) passwordWrappingKey = wrapping.clone();
                    } finally {
                        Arrays.fill(newKey, (byte) 0);
                        if (wrapping != null) Arrays.fill(wrapping, (byte) 0);
                    }
                    return null;
                });
    }

    public synchronized boolean isWiped() {
        try {
            JsonObject h = headerUnlocked();
            String generation =
                    unlockedGeneration != null
                            ? unlockedGeneration
                            : h == null ? null : Json.string(h, "generation");
            return generation != null && Files.exists(path("wiped-" + generation));
        } catch (Exception e) {
            return true;
        }
    }

    public synchronized void resetAfterCleanup() throws Exception {
        trace.step(FlowDiagnostics.Step.VAULT_RESET, FlowDiagnostics.Result.STARTED);
        try {
            resetAfterCleanupInternal();
            trace.step(FlowDiagnostics.Step.VAULT_RESET, FlowDiagnostics.Result.SUCCEEDED);
        } catch (Exception | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.VAULT_RESET, error);
            throw error;
        }
    }

    private synchronized void resetAfterCleanupInternal() throws Exception {
        locked(
                () -> {
                    JsonObject h = headerUnlocked();
                    if (h != null && !Files.exists(path("wiped-" + Json.string(h, "generation"))))
                        throw new IOException("CLEANUP_REQUIRED");
                    close();
                    Files.deleteIfExists(path("header.json"));
                    return null;
                });
    }

    public synchronized void clearLocally() throws Exception {
        trace.step(FlowDiagnostics.Step.VAULT_WIPE, FlowDiagnostics.Result.STARTED);
        try {
            clearLocallyInternal();
            trace.step(FlowDiagnostics.Step.VAULT_WIPE, FlowDiagnostics.Result.SUCCEEDED);
        } catch (Exception | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.VAULT_WIPE, error);
            throw error;
        }
    }

    private synchronized void clearLocallyInternal() throws Exception {
        locked(
                () -> {
                    JsonObject h = headerUnlocked();
                    if (h == null) return null;
                    String generation = Json.string(h, "generation");
                    JsonObject marker = Json.obj("action", "LOCAL_CLEAR");
                    marker.addProperty("vaultGeneration", generation);
                    atomic(
                            "wiped-" + generation,
                            Json.GSON.toJson(marker).getBytes(StandardCharsets.UTF_8));
                    Files.deleteIfExists(path("vault-" + generation + ".enc"));
                    removeKeys(h);
                    close();
                    return null;
                });
    }

    public Path root() {
        return root;
    }

    @Override
    public synchronized void close() {
        trace.step(FlowDiagnostics.Step.VAULT_LOCK, FlowDiagnostics.Result.STARTED);
        try {
            closeInternal();
            trace.step(FlowDiagnostics.Step.VAULT_LOCK, FlowDiagnostics.Result.SUCCEEDED);
        } catch (RuntimeException | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.VAULT_LOCK, error);
            throw error;
        }
    }

    private synchronized void closeInternal() {
        if (key != null) Arrays.fill(key, (byte) 0);
        if (passwordWrappingKey != null) Arrays.fill(passwordWrappingKey, (byte) 0);
        passwordWrappingKey = null;
        key = null;
        unlockedGeneration = null;
    }
}
