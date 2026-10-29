// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import com.google.gson.*;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

public final class MintAuthRuntime implements AutoCloseable {
    public static void logBootstrapFailure(
            Throwable error, java.util.function.Consumer<String> sink) {
        new FlowDiagnostics(sink, sink).failure(FlowDiagnostics.Step.RUNTIME_START, error);
    }

    public static final class AccountView {
        public final String id, ign, uuid, kind, status;
        public final boolean cloud, onAutoMint, savedOnDevice, needsSync;

        public String label() {
            return kind.equals("OWNED")
                    ? "Owned on Mint"
                    : kind.equals("TEMPORARY") ? "Temporary deal access" : "External - Unverified";
        }

        AccountView(JsonObject value) {
            id = Json.string(value, "id");
            ign = Json.string(value, "ign");
            uuid = Json.string(value, "uuid");
            kind = Json.string(value, "kind");
            status = Json.optional(value, "status");
            cloud = "CLOUD".equals(Json.optional(value, "source"));
            onAutoMint = AccountRecords.onMint(value);
            savedOnDevice = value.has("ssid") && !AccountRecords.locallyRemoved(value);
            needsSync = AccountRecords.needsSync(value);
        }
    }

    private final GameBridge game;
    private final StartupDiagnostics diagnostics;
    private final FlowDiagnostics trace;
    private final Path storageRoot;
    private final Vault vault;
    private final ExecutorService browserIo =
            Executors.newSingleThreadExecutor(
                    r -> {
                        Thread thread = new Thread(r, "MintAuth browser");
                        thread.setDaemon(true);
                        return thread;
                    });
    private final AccountWebsiteAction accountWebsite;
    private final PairingWebsiteAction pairingWebsite;
    private final ProtocolClient api;
    private final MinecraftJoin legacyMinecraftJoin = new MinecraftJoin();

    public boolean joinLegacyMinecraft(String uuid, String token, String digest)
            throws IOException {
        String fingerprint = uuid + ":" + Crypto.tokenHash(token);
        if (activeId == null || !Objects.equals(activeFingerprint, fingerprint)) return false;
        try {
            legacyMinecraftJoin.join(uuid, token, digest);
            return true;
        } catch (MinecraftJoin.Failure failure) {
            status = failure.getMessage();
            if (failure.reason == MinecraftJoin.Reason.INVALID_SESSION) invalidSession(fingerprint);
            throw failure;
        }
    }

    private volatile MultiplayerAccess activeMultiplayerAccess = MultiplayerAccess.UNKNOWN;

    public String multiplayerIssue() {
        return activeId == null ? null : activeMultiplayerAccess.restriction();
    }

    public String joinFailureMessage() {
        String restriction = multiplayerIssue();
        return restriction != null
                ? restriction
                : "MintAuth authorization is unavailable. Open MintAuth to continue.";
    }

    public void authenticationEvent(GameBridge.Progress progress, Throwable error) {
        trace.bridge(GameBridge.Stage.AUTHENTICATION, progress, error);
    }

    private final PlayLease lease;
    private final ScheduledExecutorService io =
            Executors.newSingleThreadScheduledExecutor(
                    r -> {
                        Thread t = new Thread(r, "MintAuth I/O");
                        t.setDaemon(true);
                        return t;
                    });
    private final ExecutorService events =
            Executors.newSingleThreadExecutor(
                    r -> {
                        Thread t = new Thread(r, "MintAuth events");
                        t.setDaemon(true);
                        return t;
                    });
    private final ScheduledExecutorService cleanup =
            Executors.newSingleThreadScheduledExecutor(
                    r -> {
                        Thread t = new Thread(r, "MintAuth cleanup");
                        t.setDaemon(true);
                        return t;
                    });
    private final InstanceRegistry instances;
    private final AtomicLong selectionRevision = new AtomicLong();
    private volatile AccountPreparation preparation;
    private volatile List<AccountView> views = Collections.emptyList();
    private volatile String status = "Open MintAuth to manage accounts.",
            pairingCode = "",
            pairingUrl = "",
            activeId,
            activeFingerprint,
            lastDestination;
    private volatile boolean busy, linked, needsPassword, theme = true, closed, streamRunning;
    private volatile boolean startupReady, welcomeSeen, welcomePresented;
    private final AtomicLong uiOperationIds = new AtomicLong();
    private final UiOperations uiCompleted = new UiOperations();
    private volatile String storageIssue;
    private volatile boolean passwordFallbackAvailable;

    public static final class UiOperation {
        public final long id;
        public final boolean succeeded;
        public final String message;

        UiOperation(long id, boolean succeeded, String message) {
            this.id = id;
            this.succeeded = succeeded;
            this.message = message;
        }
    }

    public long submittedOperation() {
        return uiOperationIds.get();
    }

    static final class UiOperations {
        private final LinkedHashMap<Long, UiOperation> finished = new LinkedHashMap<>();

        synchronized void finish(long id, boolean succeeded) {
            finish(id, succeeded, null);
        }

        synchronized void finish(long id, boolean succeeded, String message) {
            finished.put(id, new UiOperation(id, succeeded, message));
            while (finished.size() > 64) finished.remove(finished.keySet().iterator().next());
        }

        synchronized UiOperation get(long id) {
            return finished.get(id);
        }
    }

    public UiOperation completedOperation(long id) {
        return uiCompleted.get(id);
    }

    public boolean startupReady() {
        return startupReady;
    }

    public String storageIssue() {
        return storageIssue;
    }

    public boolean canCreatePasswordVault() {
        return passwordFallbackAvailable;
    }

    public String nativeStorageName() {
        String os = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT);
        return os.contains("mac") || os.contains("darwin")
                ? "macOS Keychain"
                : os.contains("win") ? "Windows secure storage" : "system key storage";
    }

    public String storageRecoveryDescription() {
        if ("VAULT_REVOKED".equals(storageIssue))
            return "Set up MintAuth again to add or link your accounts.";
        return "Couldn't open "
                + nativeStorageName()
                + ". Unlock it or allow access if prompted, then retry. "
                + (passwordFallbackAvailable
                        ? "A separate password is optional."
                        : "Your saved accounts have been kept.");
    }

    public void prepareGuidedStorage() {
        submit(
                StartupDiagnostics.Operation.STORAGE,
                () -> {
                    if (vault.isWiped()) throw new Vault.Locked("VAULT_REVOKED");
                    if (vault.header() == null || needsPassword) {
                        vault.unlock(null, false);
                        initializeKey();
                    } else vault.read();
                    loadViews();
                    needsPassword = false;
                    storageIssue = null;
                    passwordFallbackAvailable = false;
                });
    }

    private volatile boolean automaticUpdates = true;
    private volatile UpdateService updates;
    private volatile String updateNotice = "Updates require an official JAR installation.";
    private volatile long lastUpdateCheck;
    private volatile boolean updateChecking;
    private final ExecutorService updateIo =
            Executors.newSingleThreadExecutor(
                    r -> {
                        Thread thread = new Thread(r, "MintAuth updates");
                        thread.setDaemon(true);
                        return thread;
                    });
    private volatile Crypto.Signer signer;
    private volatile long nextPairPoll, lastCleanup, lastHeartbeat, lastLocalCheck;
    private volatile int recoveryCount;
    private volatile String moveAccount;
    private final Path preferences;
    private volatile JsonObject enrollmentHeader;
    private volatile String completedCleanup;
    private volatile boolean pendingApply;
    private volatile long activeOfflineUntil, activeKnownExpiry, activeOfflineDeadline;
    private volatile String activeSource;
    private volatile boolean activeRejected, identityUnsafe;
    private volatile boolean automaticReconnect;
    private final AtomicLong joinRevision = new AtomicLong();
    private volatile long recoveryJoin = -1;
    private volatile String recoveryDestination;

    public MintAuthRuntime(GameBridge bridge) throws Exception {
        this(bridge, Vault.defaultRoot());
    }

    public MintAuthRuntime(GameBridge bridge, Path root) throws Exception {
        this(
                bridge,
                root,
                new Vault(root, NativeStores.forPlatform(root)),
                new ProtocolClient(),
                true);
    }

    MintAuthRuntime(
            GameBridge bridge,
            Path root,
            Vault storage,
            ProtocolClient protocol,
            boolean background)
            throws Exception {
        game = bridge;
        trace = new FlowDiagnostics(bridge::logDiagnostic, bridge::logFailureDiagnostic);
        storageRoot = root;
        trace.step(FlowDiagnostics.Step.RUNTIME_START, FlowDiagnostics.Result.STARTED);
        api = protocol;
        api.setDiagnostics(trace);
        legacyMinecraftJoin.setDiagnostics(trace);
        accountWebsite = new AccountWebsiteAction(browserIo, bridge::openWebsite, trace);
        diagnostics = new StartupDiagnostics(bridge::logDiagnostic);
        pairingWebsite =
                new PairingWebsiteAction(
                        browserIo,
                        bridge::openWebsite,
                        error ->
                                diagnostics.operationFailure(
                                        StartupDiagnostics.Operation.BROWSER, error),
                        trace);
        vault = storage;
        vault.setDiagnostics(trace);
        game.setDiagnostics(trace::bridge);
        lease = new PlayLease(root);
        lease.setDiagnostics(trace);
        instances = new InstanceRegistry(root);
        instances.setDiagnostics(trace);
        preferences = root.resolve("preferences.json");
        if (Files.exists(preferences)
                && !Files.isSymbolicLink(preferences)
                && Files.size(preferences) < 8192)
            try {
                JsonObject p =
                        Json.object(
                                new String(Files.readAllBytes(preferences), StandardCharsets.UTF_8),
                                8192);
                theme = !p.has("theme") || p.get("theme").getAsBoolean();
                automaticUpdates =
                        !p.has("automaticUpdates") || p.get("automaticUpdates").getAsBoolean();
                welcomeSeen = p.has("welcomeComplete") && p.get("welcomeComplete").getAsBoolean();
            } catch (Exception ignored) {
            }
        if (background) {
            io.scheduleWithFixedDelay(this::maintenance, 0, 1, TimeUnit.SECONDS);
            cleanup.scheduleWithFixedDelay(
                    () -> {
                        try {
                            checkCleanup();
                            String fingerprint = activeFingerprint;
                            if (fingerprint != null && !identityUnsafe)
                                checkBeforeAuthentication(fingerprint);
                        } catch (Exception error) {
                            trace.failure(FlowDiagnostics.Step.CLEANUP_CHECK, error);
                        }
                    },
                    0,
                    30,
                    TimeUnit.SECONDS);
            io.execute(
                    () -> {
                        try {
                            trace.step(
                                    FlowDiagnostics.Step.STARTUP_HEADER,
                                    FlowDiagnostics.Result.STARTED);
                            JsonObject startupHeader = vault.header();
                            trace.storage(storageRoot, startupHeader);
                            trace.step(
                                    FlowDiagnostics.Step.STARTUP_HEADER,
                                    startupHeader == null
                                            ? FlowDiagnostics.Result.EMPTY
                                            : FlowDiagnostics.Result.EXISTING);
                            if (startupHeader != null) {
                                try {
                                    checkCleanup();
                                } catch (java.io.IOException error) {
                                    trace.failure(FlowDiagnostics.Step.CLEANUP_CHECK, error);
                                }
                                if (!vault.isWiped()) {
                                    trace.step(
                                            FlowDiagnostics.Step.VAULT_UNLOCK,
                                            FlowDiagnostics.Result.STARTED);
                                    vault.unlock(null, false);
                                    trace.step(
                                            FlowDiagnostics.Step.VAULT_UNLOCK,
                                            FlowDiagnostics.Result.SUCCEEDED);
                                    loadSavedAccounts();
                                } else storageIssue = "VAULT_REVOKED";
                            }
                        } catch (Exception | LinkageError e) {
                            trace.failure(FlowDiagnostics.Step.RUNTIME_START, e);
                            diagnostics.operationFailure(StartupDiagnostics.Operation.STARTUP, e);
                            needsPassword = true;
                            failure(e);
                        } finally {
                            startupReady = true;
                            trace.step(
                                    FlowDiagnostics.Step.RUNTIME_START,
                                    needsPassword
                                            ? FlowDiagnostics.Result.FAILED
                                            : FlowDiagnostics.Result.SUCCEEDED);
                            reportLocalState();
                        }
                        checkWebsiteAtStartup();
                    });
        } else startupReady = true;
    }

    public synchronized boolean consumeWelcome() {
        if (!startupReady || welcomeSeen || welcomePresented || linked) return false;
        welcomePresented = true;
        return true;
    }

    public void dismissWelcome() {
        welcomeSeen = true;
        savePreference("welcomeComplete", new JsonPrimitive(true));
    }

    public void configureUpdates(String target, Path gameRoot, Path installedJar) {
        updateIo.execute(() -> diagnostics.artifact(target, installedJar));
        try {
            updates = new UpdateService(target, gameRoot, installedJar, trace);
            updateNotice = null;
            updateIo.execute(
                    () -> {
                        if (automaticUpdates) updates.resume();
                        else updates.cancel();
                    });
        } catch (Exception | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.UPDATE_SETUP, error);
            updateNotice =
                    "Automatic updates are unavailable for this installation. Use the downloads"
                            + " page.";
        }
    }

    public boolean automaticUpdates() {
        return automaticUpdates;
    }

    public String updateStatus() {
        return updateNotice != null
                ? updateNotice
                : updates == null ? "Updates are unavailable." : updates.message();
    }

    public void toggleAutomaticUpdates() {
        automaticUpdates = !automaticUpdates;
        trace.step(
                FlowDiagnostics.Step.UPDATE_SETTING,
                automaticUpdates
                        ? FlowDiagnostics.Result.ENABLED
                        : FlowDiagnostics.Result.DISABLED);
        savePreference("automaticUpdates", new JsonPrimitive(automaticUpdates));
        if (!automaticUpdates && updates != null) updateIo.execute(() -> updates.cancel());
    }

    public void openDownloadsWebsite() {
        trace.step(FlowDiagnostics.Step.DOWNLOADS_BROWSER, FlowDiagnostics.Result.STARTED);
        try {
            game.openWebsite(URI.create(ProtocolClient.ORIGIN + "/download/mintauth"));
            trace.step(FlowDiagnostics.Step.DOWNLOADS_BROWSER, FlowDiagnostics.Result.SUCCEEDED);
        } catch (Exception error) {
            trace.failure(FlowDiagnostics.Step.DOWNLOADS_BROWSER, error);
            updateNotice = "Open automint.online/download/mintauth in your browser.";
        }
    }

    public synchronized void checkUpdates() {
        if (updates == null || closed || updateChecking) return;
        lastUpdateCheck = System.currentTimeMillis();
        if (!linked || signer == null || needsPassword) {
            updateNotice = "Link AutoMint and unlock storage for automatic updates.";
            return;
        }
        updateChecking = true;
        updateNotice = null;
        updateIo.execute(
                () -> {
                    try {
                        JsonObject catalog = call("GET", "updates", null);
                        updates.check(
                                catalog,
                                (key, destination, maximum) -> {
                                    call(
                                            "GET",
                                            "authorization",
                                            null);
                                    JsonObject auth = authorization(vault.read());
                                    api.downloadUpdate(
                                            key,
                                            destination,
                                            maximum,
                                            Json.string(auth, "access_token"),
                                            signer);
                                });
                    } catch (Exception | LinkageError error) {
                        trace.failure(FlowDiagnostics.Step.UPDATE_CHECK, error);
                        updateNotice =
                                "Updates could not be checked. Retry later or use the downloads"
                                        + " page.";
                        if (error instanceof ProtocolClient.ApiException
                                && ((ProtocolClient.ApiException) error).grantLost())
                            failure(error);
                    } finally {
                        updateChecking = false;
                    }
                });
    }

    public List<AccountView> accounts() {
        return views;
    }

    public List<AccountView> accountCards() {
        return AccountGroups.cards(views);
    }

    public AccountView account(String id) {
        for (AccountView entry : views) if (entry.id.equals(id)) return entry;
        return null;
    }

    public List<AccountView> accountSources(String uuid) {
        return AccountGroups.sources(views, uuid);
    }

    public boolean isPlaying(AccountView account) {
        String playing = playingAccountId();
        AccountView active = account(playing);
        return active != null && account != null && AccountGroups.same(active.uuid, account.uuid);
    }

    public boolean canSwitchIdentity() {
        return !game.worldOpen() && !busy;
    }

    public boolean canUseMintSession(AccountView account) {
        return isPlaying(account)
                && !account.id.equals(playingAccountId())
                && account.onAutoMint
                && !account.cloud
                && AccountGroups.available(account);
    }

    public String playingSourceLabel() {
        AccountView active = account(playingAccountId());
        if (active == null) return "";
        if (!active.onAutoMint) return "pasted SSID";
        return active.cloud ? "saved SSID" : "Mint session";
    }

    public String activeIgn() {
        String selected = activeId;
        if (selected == null) return null;
        for (AccountView entry : views) if (entry.id.equals(selected)) return entry.ign;
        return null;
    }

    public String status() {
        return status;
    }

    public boolean busy() {
        return busy;
    }

    public String pairingCode() {
        return pairingCode;
    }

    public String accountMenuLabel() {
        String ign = activeIgn();
        if (ign != null) return "Accounts / " + ign;
        if (!startupReady) return "Accounts / Loading...";
        if (needsPassword) return "Accounts / Unlock accounts";
        return linked ? "Accounts / AutoMint linked" : "Accounts / Link AutoMint";
    }

    public boolean linked() {
        return linked;
    }

    public boolean needsPassword() {
        return needsPassword;
    }

    public boolean theme() {
        return theme;
    }

    public String moveAccount() {
        return moveAccount;
    }

    public String activeId() {
        return activeId;
    }

    public String playingAccountId() {
        String id = activeId, fingerprint = activeFingerprint;
        if (id == null || fingerprint == null || identityUnsafe || activeRejected) return null;
        return fingerprint.equals(game.currentFingerprint()) ? id : null;
    }

    public void logRealmsGate(boolean allowed) {
        trace.state(
                FlowDiagnostics.Step.REALMS_GATE,
                allowed ? FlowDiagnostics.Result.ALLOWED : FlowDiagnostics.Result.BLOCKED);
    }

    public void logUiAction() {
        trace.step(FlowDiagnostics.Step.UI_ACTION, FlowDiagnostics.Result.STARTED);
    }

    public void logUiFailure(Throwable error) {
        trace.failure(FlowDiagnostics.Step.UI_ACTION, error);
    }

    public void logUiStep(String name) {
        trace.ui(name);
    }

    public void open() {
        trace.step(FlowDiagnostics.Step.UI_OPEN, FlowDiagnostics.Result.STARTED);
        submit(
                () -> {
                    if (vault.header() == null) {
                        vault.unlock(null, false);
                        initializeKey();
                    } else if (!vault.isWiped()) loadViews();
                });
    }

    public void unlock(char[] password, boolean newPasswordFallback) {
        final char[] copy = password.clone();
        Arrays.fill(password, '\0');
        submit(
                StartupDiagnostics.Operation.UNLOCK,
                () -> {
                    try {
                        vault.unlock(copy, newPasswordFallback);
                        needsPassword = false;
                        storageIssue = null;
                        passwordFallbackAvailable = false;
                        loadSavedAccounts();
                    } finally {
                        Arrays.fill(copy, '\0');
                    }
                });
    }

    public void toggleTheme() {
        theme = !theme;
        trace.step(
                FlowDiagnostics.Step.THEME_SETTING,
                theme ? FlowDiagnostics.Result.ENABLED : FlowDiagnostics.Result.DISABLED);
        savePreference("theme", new JsonPrimitive(theme));
    }

    private void savePreference(String name, JsonElement value) {
        trace.step(FlowDiagnostics.Step.PREFERENCE_SAVE, FlowDiagnostics.Result.QUEUED);
        io.execute(
                () -> {
                    trace.step(
                            FlowDiagnostics.Step.PREFERENCE_SAVE, FlowDiagnostics.Result.STARTED);
                    try (java.nio.channels.FileChannel channel =
                                    java.nio.channels.FileChannel.open(
                                            preferences.resolveSibling("preferences.lock"),
                                            StandardOpenOption.CREATE,
                                            StandardOpenOption.WRITE,
                                            LinkOption.NOFOLLOW_LINKS);
                            java.nio.channels.FileLock lock = channel.lock()) {
                        JsonObject p = new JsonObject();
                        if (Files.exists(preferences)
                                && Files.size(preferences) < 8192
                                && !Files.isSymbolicLink(preferences))
                            p =
                                    Json.object(
                                            new String(
                                                    Files.readAllBytes(preferences),
                                                    StandardCharsets.UTF_8),
                                            8192);
                        p.add(name, value);
                        Path temp = preferences.resolveSibling("prefs-" + UUID.randomUUID());
                        Files.write(
                                temp,
                                Json.GSON.toJson(p).getBytes(StandardCharsets.UTF_8),
                                StandardOpenOption.CREATE_NEW);
                        Files.move(
                                temp,
                                preferences,
                                StandardCopyOption.ATOMIC_MOVE,
                                StandardCopyOption.REPLACE_EXISTING);
                        trace.step(
                                FlowDiagnostics.Step.PREFERENCE_SAVE,
                                FlowDiagnostics.Result.SUCCEEDED);
                    } catch (Exception error) {
                        trace.failure(FlowDiagnostics.Step.PREFERENCE_SAVE, error);
                        status = "Preferences could not be saved.";
                    }
                });
    }

    private void reportLocalState() {
        try {
            StartupDiagnostics.Storage state =
                    vault.isWiped()
                            ? StartupDiagnostics.Storage.CLEARED
                            : needsPassword
                                    ? StartupDiagnostics.Storage.LOCKED
                                    : signer != null
                                            ? StartupDiagnostics.Storage.UNLOCKED
                                            : vault.header() == null
                                                    ? StartupDiagnostics.Storage.NOT_INITIALIZED
                                                    : StartupDiagnostics.Storage.UNAVAILABLE;
            JsonObject auth =
                    state == StartupDiagnostics.Storage.UNLOCKED
                            ? vault.read().getAsJsonObject("authorization")
                            : null;
            diagnostics.local(state, auth, signer != null && "SOFTWARE".equals(signer.reference()));
        } catch (Exception | LinkageError ignored) {
            diagnostics.local(StartupDiagnostics.Storage.UNAVAILABLE, null, false);
        }
    }

    private void checkWebsiteAtStartup() {
        try {
            if (linked && signer != null) {
                lastHeartbeat = System.currentTimeMillis();
                call("GET", "authorization", null);
            } else {
                api.request("GET", "keys", null, null, null);
                diagnostics.website(
                        StartupDiagnostics.Connection.REACHABLE,
                        needsPassword
                                ? StartupDiagnostics.Authorization.LOCKED
                                : StartupDiagnostics.Authorization.NOT_LINKED,
                        null,
                        null);
            }
        } catch (Exception error) {
            diagnostics.websiteFailure(error);
            if (error instanceof ProtocolClient.ApiException
                    && ((ProtocolClient.ApiException) error).grantLost()) failure(error);
        } catch (LinkageError ignored) {
            diagnostics.website(
                    StartupDiagnostics.Connection.UNCONFIRMED,
                    StartupDiagnostics.Authorization.CHECK_FAILED,
                    null,
                    null);
        }
    }

    private interface Work {
        void run() throws Exception;
    }

    private void submit(Work work) {
        submit(StartupDiagnostics.Operation.OTHER, work);
    }

    private void submit(StartupDiagnostics.Operation operation, Work work) {
        if (closed) return;
        final long operationId = uiOperationIds.incrementAndGet();
        trace.worker(operation, operationId, FlowDiagnostics.Result.QUEUED);
        io.execute(
                () -> {
                    boolean succeeded = false;
                    busy = true;
                    trace.worker(operation, operationId, FlowDiagnostics.Result.STARTED);
                    try {
                        work.run();
                        succeeded = true;
                    } catch (Exception | LinkageError e) {
                        trace.failure(FlowDiagnostics.Step.WORKER, e);
                        diagnostics.operationFailure(operation, e);
                        failure(e);
                    } finally {
                        busy = false;
                        trace.worker(
                                operation,
                                operationId,
                                succeeded
                                        ? FlowDiagnostics.Result.SUCCEEDED
                                        : FlowDiagnostics.Result.FAILED);
                        uiCompleted.finish(operationId, succeeded, status);
                    }
                });
    }

    private void failure(Throwable error) {
        if (error instanceof Vault.Locked) {
            needsPassword = true;
            storageIssue = error.getMessage();
            passwordFallbackAvailable = false;
            try {
                passwordFallbackAvailable = vault.header() == null;
            } catch (Exception ignored) {
            }
            status = "Unlock secure storage; existing saved data has been kept.";
            return;
        }
        if (error instanceof ProtocolClient.ApiException) {
            ProtocolClient.ApiException apiError = (ProtocolClient.ApiException) error;
            if (apiError.grantLost()) {
                clearLinkedUse();
                status =
                        apiError.code.equals("MINTAUTH_REVOKED")
                                ? "This device was revoked. Checking its cleanup request…"
                                : "Mint access is unavailable. Link again or choose another"
                                        + " account.";
                return;
            }
            if (apiError.authorityLost()) {
                status = "This account is unavailable. Refresh or choose another account.";
                return;
            }
            if (apiError.code.equals("SESSION_ACCOUNT_RESTRICTED")) {
                status = "This account is locked. Resolve it on AutoMint, then try again.";
                return;
            }
            if (Arrays.asList("SESSION_SETTINGS_CHANGED", "SESSION_DELIVERY_STALE", "SESSION_UPGRADE_REQUIRED")
                    .contains(apiError.code)) {
                status = "This session changed on Mint. Select the account again to get its current session.";
                return;
            }
            if (Arrays.asList("SESSION_TOKEN_UNAVAILABLE", "SESSION_CHECK_UNAVAILABLE", "SESSION_CHECK_EXPIRED", "SESSION_TOKEN_EXPIRING")
                    .contains(apiError.code)) {
                status = "Mint couldn't get a playable session. Try this account again shortly.";
                return;
            }
            if (apiError.code.equals("AUTHORIZATION_PENDING")) return;
            if (apiError.code.equals("EXTERNAL_CONFLICT")) {
                status = "This sign-in changed during sync. Refresh your accounts and try again.";
                return;
            }
            if (apiError.code.equals("USE_MANAGED_ACCOUNT")) {
                status = "Use the eligible Mint account from your account list.";
                return;
            }
            if (apiError.code.equals("SESSION_REQUEST_COOLDOWN")
                    || apiError.code.equals("RATE_LIMITED")) {
                status = "Please wait before checking this account again.";
                return;
            }
            if (apiError.code.equals("EXTERNAL_TOKEN_REJECTED")) {
                status =
                        "MANAGED".equals(activeSource)
                                ? "Expired / rejected SSID. Select this Mint account to retry"
                                        + " recovery."
                                : "Expired / rejected SSID. Paste a replacement or secure the"
                                        + " account with Mint.";
                return;
            }
        }
        status = OperationFailures.message(error);
    }

    private JsonObject records(JsonObject data) {
        if (!data.has("accounts")) data.add("accounts", new JsonObject());
        return data.getAsJsonObject("accounts");
    }

    private synchronized void initializeKey() throws Exception {
        trace.step(FlowDiagnostics.Step.KEY_RESOLVE, FlowDiagnostics.Result.STARTED);
        if (signer instanceof AutoCloseable) ((AutoCloseable) signer).close();
        signer = null;
        final JsonObject header = vault.header();
        enrollmentHeader = header.deepCopy();
        instances.report(Json.string(header, "generation"), false);
        signer =
                vault.update(
                        data -> {
                            if (data.has("deviceKey")) {
                                trace.step(
                                        FlowDiagnostics.Step.KEY_EXISTING,
                                        FlowDiagnostics.Result.STARTED);
                                Crypto.Signer existing = signer(data.getAsJsonObject("deviceKey"));
                                trace.step(
                                        FlowDiagnostics.Step.KEY_EXISTING,
                                        FlowDiagnostics.Result.SUCCEEDED);
                                return existing;
                            }
                            trace.step(
                                    FlowDiagnostics.Step.KEY_CREATE,
                                    FlowDiagnostics.Result.STARTED);
                            String prior = Json.optional(header, "keyReference");
                            Crypto.Signer hardware =
                                    prior != null && !prior.equals("SOFTWARE")
                                            ? HardwareKeys.open(prior)
                                            : HardwareKeys.create(
                                                    Json.string(header, "generation"));
                            trace.step(
                                    FlowDiagnostics.Step.KEY_CREATE,
                                    hardware == null
                                            ? FlowDiagnostics.Result.FALLBACK
                                            : FlowDiagnostics.Result.SUCCEEDED);
                            JsonObject key = new JsonObject();
                            if (hardware != null) {
                                key.addProperty("reference", hardware.reference());
                                key.add("publicKey", hardware.publicJwk());
                            } else {
                                KeyPair pair = Crypto.ecKey();
                                key.addProperty("reference", "SOFTWARE");
                                key.addProperty(
                                        "privateKey", Crypto.b64(pair.getPrivate().getEncoded()));
                                key.add("publicKey", Crypto.publicJwk(pair.getPublic()));
                            }
                            data.add("deviceKey", key);
                            return hardware != null ? hardware : signer(key);
                        });
        if (vault.isWiped()) {
            if (signer instanceof AutoCloseable) ((AutoCloseable) signer).close();
            signer = null;
            throw new Vault.Locked("VAULT_REVOKED");
        }
        enrollmentHeader = vault.header();
        trace.step(FlowDiagnostics.Step.KEY_READY, FlowDiagnostics.Result.SUCCEEDED);
    }

    private Crypto.Signer signer(JsonObject key) throws Exception {
        String reference = Json.string(key, "reference");
        return reference.equals("SOFTWARE")
                ? Crypto.software(
                        Crypto.privateKey(Json.string(key, "privateKey")),
                        key.getAsJsonObject("publicKey"))
                : HardwareKeys.open(reference);
    }

    private JsonObject authorization(JsonObject data) throws Exception {
        if (!data.has("authorization"))
            throw new ProtocolClient.ApiException("MINTAUTH_RELINK_REQUIRED", 401);
        return data.getAsJsonObject("authorization");
    }

    private JsonObject call(String method, String path, JsonObject body) throws Exception {
        boolean checking = method.equals("GET") && path.equals("authorization");
        if (checking)
            trace.step(FlowDiagnostics.Step.AUTHORITY_CHECK, FlowDiagnostics.Result.STARTED);
        try {
            JsonObject result = authorizedCall(method, path, body);
            if (checking) {
                trace.step(FlowDiagnostics.Step.AUTHORITY_CHECK, FlowDiagnostics.Result.SUCCEEDED);
                try {
                    diagnostics.website(
                            StartupDiagnostics.Connection.REACHABLE,
                            StartupDiagnostics.Authorization.VALID,
                            authorization(vault.read()),
                            null);
                } catch (Exception | LinkageError ignored) {
                }
            }
            return result;
        } catch (Exception error) {
            if (checking) {
                trace.failure(FlowDiagnostics.Step.AUTHORITY_CHECK, error);
                diagnostics.websiteFailure(error);
            }
            throw error;
        }
    }

    private JsonObject authorizedCall(String method, String path, JsonObject body)
            throws Exception {
        JsonObject auth = authorization(vault.read());
        String access = Json.string(auth, "access_token");
        try {
            return api.request(method, path, body, access, signer);
        } catch (ProtocolClient.ApiException e) {
            if (!e.accessExpired()) throw e;
        }
        trace.step(FlowDiagnostics.Step.TOKEN_ROTATE_LOCK, FlowDiagnostics.Result.STARTED);
        JsonObject refreshed =
                vault.update(
                        data -> {
                            JsonObject current = authorization(data);
                            if (!Json.string(current, "access_token").equals(access))
                                return current.deepCopy();
                            String requestId = Json.optional(data, "rotationRequestId");
                            if (requestId == null) {
                                requestId = UUID.randomUUID().toString();
                                data.addProperty("rotationRequestId", requestId);
                            }
                            return current.deepCopy();
                        });
        refreshed =
                vault.update(
                        data -> {
                            JsonObject current = authorization(data);
                            if (!Json.string(current, "access_token").equals(access))
                                return current.deepCopy();
                            JsonObject bodyRefresh = Json.obj("grant_type", "refresh_token");
                            bodyRefresh.addProperty(
                                    "refresh_token", Json.string(current, "refresh_token"));
                            bodyRefresh.addProperty(
                                    "request_id", Json.string(data, "rotationRequestId"));
                            trace.step(
                                    FlowDiagnostics.Step.TOKEN_ROTATE_REQUEST,
                                    FlowDiagnostics.Result.STARTED);
                            JsonObject response =
                                    api.request(
                                            "POST",
                                            "token",
                                            bodyRefresh,
                                            Json.string(current, "refresh_token"),
                                            signer);
                            if (!Json.string(response, "device_id")
                                            .equals(Json.string(current, "device_id"))
                                    || !Json.string(response, "vault_generation")
                                            .equals(Json.string(current, "vault_generation")))
                                throw new GeneralSecurityException("GRANT_BINDING");
                            data.add("authorization", response);
                            trace.step(
                                    FlowDiagnostics.Step.TOKEN_ROTATE_SAVE,
                                    FlowDiagnostics.Result.STARTED);
                            data.remove("rotationRequestId");
                            return response.deepCopy();
                        });
        trace.step(FlowDiagnostics.Step.TOKEN_ROTATE_SAVE, FlowDiagnostics.Result.SUCCEEDED);
        return api.request(method, path, body, Json.string(refreshed, "access_token"), signer);
    }

    public void beginLink() {
        trace.step(FlowDiagnostics.Step.LINK_CLICK, FlowDiagnostics.Result.STARTED);
        submit(
                StartupDiagnostics.Operation.LINK,
                () -> {
                    trace.step(FlowDiagnostics.Step.LINK_GUARD, FlowDiagnostics.Result.STARTED);
                    if (game.worldOpen()) {
                        trace.step(FlowDiagnostics.Step.LINK_GUARD, FlowDiagnostics.Result.SKIPPED);
                        status = "Leave the current game before linking.";
                        return;
                    }
                    checkCleanup();
                    JsonObject header = vault.header();
                    trace.storage(storageRoot, header);
                    if (header == null) {
                        vault.unlock(null, false);
                        initializeKey();
                        header = vault.header();
                    }
                    if (vault.isWiped()) {
                        status =
                                "Device cleanup is complete. Reset the cleared vault to link"
                                        + " again.";
                        return;
                    }
                    JsonObject data = vault.read();
                    if (data.has("authorization")) {
                        trace.step(
                                FlowDiagnostics.Step.LINK_EXISTING,
                                FlowDiagnostics.Result.EXISTING);
                        if (signer == null) initializeKey();
                        loadViews();
                        pairingWebsite.clear();
                        status =
                                "This device is already linked. Unlink & clear it before changing"
                                        + " the linked profile.";
                        return;
                    }
                    if (header.has("deviceId")) {
                        trace.step(FlowDiagnostics.Step.LINK_REKEY, FlowDiagnostics.Result.STARTED);
                        clearActive("Linking again. Local accounts will return after approval.");
                        vault.beginRelink();
                        if (signer instanceof AutoCloseable) ((AutoCloseable) signer).close();
                        signer = null;
                        initializeKey();
                        header = vault.header();
                    }
                    if (signer == null) initializeKey();
                    final JsonObject h = header;
                    JsonObject response =
                            vault.update(
                                    current -> {
                                        if (current.has("pairing")) {
                                            trace.step(
                                                    FlowDiagnostics.Step.PAIRING_REQUEST,
                                                    FlowDiagnostics.Result.EXISTING);
                                            return current.getAsJsonObject("pairing").deepCopy();
                                        }
                                        trace.step(
                                                FlowDiagnostics.Step.PAIRING_REQUEST,
                                                FlowDiagnostics.Result.STARTED);
                                        JsonObject body = new JsonObject();
                                        body.add("publicKey", signer.publicJwk());
                                        body.addProperty(
                                                "vaultGeneration", Json.string(h, "generation"));
                                        body.addProperty(
                                                "deviceName", "Minecraft on " + platform());
                                        body.addProperty("platform", platform());
                                        body.addProperty(
                                                "cleanupLocator", Json.string(h, "cleanupLocator"));
                                        body.addProperty(
                                                "cleanupReceipt", Json.string(h, "cleanupReceipt"));
                                        JsonObject pair =
                                                api.request(
                                                        "POST", "device/code", body, null, signer);
                                        pair.addProperty(
                                                "deadline", System.currentTimeMillis() + 600000);
                                        current.add("pairing", pair);
                                        return pair.deepCopy();
                                    });
                    pairingCode = Json.string(response, "user_code");
                    pairingUrl = Json.string(response, "verification_uri_complete");
                    if (!PairingWebsiteAction.uri(pairingCode).toASCIIString().equals(pairingUrl))
                        throw new GeneralSecurityException("PAIRING_WEBSITE_INVALID");
                    pairingWebsite.begin(pairingCode);
                    status = "Approve this code on AutoMint, then return here.";
                });
    }

    public void openPairingWebsite() {
        if (!closed) pairingWebsite.open();
    }

    public String pairingWebsiteNotice() {
        return pairingWebsite.notice();
    }

    public boolean pairingWebsiteOpening() {
        return pairingWebsite.opening();
    }

    public void copyPairingWebsiteLink() {
        try {
            game.copyWebsiteLink(pairingWebsite.link());
            pairingWebsite.copied(true);
        } catch (Exception | LinkageError error) {
            pairingWebsite.copied(false);
        }
    }

    public void resetClearedVault() {
        submit(
                StartupDiagnostics.Operation.RESET,
                () -> {
                    checkCleanup();
                    vault.resetAfterCleanup();
                    vault.unlock(null, false);
                    initializeKey();
                    loadViews();
                    needsPassword = false;
                    storageIssue = null;
                    passwordFallbackAvailable = false;
                    status = "Ready to link again.";
                });
    }

    private void pollPairing() throws Exception {
        JsonObject data = vault.read();
        if (!data.has("pairing")) return;
        trace.step(FlowDiagnostics.Step.PAIRING_POLL, FlowDiagnostics.Result.STARTED);
        JsonObject pair = data.getAsJsonObject("pairing");
        if (pair.get("deadline").getAsLong() < System.currentTimeMillis()) {
            vault.update(
                    d -> {
                        d.remove("pairing");
                        return null;
                    });
            pairingCode = "";
            pairingUrl = "";
            pairingWebsite.clear();
            trace.step(FlowDiagnostics.Step.PAIRING_EXPIRED, FlowDiagnostics.Result.CANCELLED);
            status = "Pairing expired. Start linking again.";
            return;
        }
        JsonObject body = Json.obj("grant_type", "urn:ietf:params:oauth:grant-type:device_code");
        body.addProperty("device_code", Json.string(pair, "device_code"));
        try {
            JsonObject token = api.request("POST", "token", body, null, signer);
            trace.step(FlowDiagnostics.Step.PAIRING_TOKEN, FlowDiagnostics.Result.SUCCEEDED);
            String generation = Json.string(vault.header(), "generation");
            if (!generation.equals(Json.string(token, "vault_generation")))
                throw new GeneralSecurityException("GRANT_BINDING");
            trace.step(FlowDiagnostics.Step.GRANT_BIND, FlowDiagnostics.Result.STARTED);
            vault.bind(Json.string(token, "device_id"), generation);
            trace.step(FlowDiagnostics.Step.GRANT_BIND, FlowDiagnostics.Result.SUCCEEDED);
            trace.step(FlowDiagnostics.Step.GRANT_SAVE, FlowDiagnostics.Result.STARTED);
            enrollmentHeader = vault.header();
            vault.update(
                    d -> {
                        d.add("authorization", token);
                        d.remove("pairing");
                        if (d.has("pendingLocalAccounts")) {
                            for (Map.Entry<String, JsonElement> item :
                                    d.getAsJsonObject("pendingLocalAccounts").entrySet())
                                records(d).add(item.getKey(), item.getValue());
                            d.remove("pendingLocalAccounts");
                        }
                        return null;
                    });
            trace.step(FlowDiagnostics.Step.GRANT_SAVE, FlowDiagnostics.Result.SUCCEEDED);
            linked = true;
            diagnostics.website(
                    StartupDiagnostics.Connection.REACHABLE,
                    StartupDiagnostics.Authorization.VALID,
                    token,
                    null);
            pairingCode = "";
            pairingWebsite.clear();
            refreshLibrary();
            trace.step(FlowDiagnostics.Step.LINK_COMPLETE, FlowDiagnostics.Result.SUCCEEDED);
            status = "Linked. Choose an account and Play.";
        } catch (ProtocolClient.ApiException e) {
            if (Arrays.asList("ACCESS_DENIED", "EXPIRED_TOKEN", "INVALID_GRANT").contains(e.code)) {
                vault.update(
                        d -> {
                            d.remove("pairing");
                            return null;
                        });
                pairingCode = "";
                pairingUrl = "";
                pairingWebsite.clear();
                trace.failure(FlowDiagnostics.Step.PAIRING_DENIED, e);
                status = "Linking was denied or expired. Start linking again when ready.";
            } else if (!e.code.equals("AUTHORIZATION_PENDING") && !e.code.equals("SLOW_DOWN"))
                throw e;
            else trace.failure(FlowDiagnostics.Step.PAIRING_POLL, e);
        }
    }

    private void loadViews() throws Exception {
        JsonObject data = vault.read();
        linked = data.has("authorization");
        List<AccountView> next = new ArrayList<>();
        for (Map.Entry<String, JsonElement> entry : records(data).entrySet())
            if (!entry.getValue().getAsJsonObject().has("hidden"))
                next.add(new AccountView(entry.getValue().getAsJsonObject()));
        views = Collections.unmodifiableList(next);
        trace.library(next.size(), linked);
        reportLocalState();
    }

    public void refresh() {
        submit(this::refreshLibrary);
    }

    public AccountPreparation preparation() {
        return preparation;
    }

    public void cancelPreparation() {
        trace.step(FlowDiagnostics.Step.ACCOUNT_PREPARE, FlowDiagnostics.Result.CANCELLED);
        AccountPreparation attempt = preparation;
        if (attempt != null) attempt.cancel();
        selectionRevision.incrementAndGet();
    }

    private void checkPreparation(long revision) {
        if (revision != selectionRevision.get() || closed) throw new CancellationException();
        AccountPreparation attempt = preparation;
        if (attempt != null && attempt.revision == revision)
            attempt.checkCurrent(selectionRevision.get(), closed);
    }

    private void preparationProgress(
            long revision, boolean userSelected, AccountPreparation.Phase phase, String message) {
        if (!userSelected || revision != selectionRevision.get() || closed) return;
        AccountPreparation attempt = preparation;
        if (attempt != null && attempt.revision == revision) attempt.update(phase, message);
    }

    private void refreshLibrary() throws Exception {
        trace.step(FlowDiagnostics.Step.LOAD_LIBRARY, FlowDiagnostics.Result.STARTED);
        try {
            refreshLibraryInternal();
            trace.step(FlowDiagnostics.Step.LOAD_LIBRARY, FlowDiagnostics.Result.SUCCEEDED);
        } catch (Exception | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.LOAD_LIBRARY, error);
            throw error;
        }
    }

    private void refreshLibraryInternal() throws Exception {
        status = "Refreshing your AutoMint accounts...";
        JsonObject auth = authorization(vault.read());
        JsonArray all = new JsonArray();
        try {
            for (JsonElement account : call("GET", "accounts", null).getAsJsonArray("accounts"))
                all.add(account);
        } catch (ProtocolClient.ApiException e) {
            if (!e.code.equals("MINTAUTH_DISABLED")) throw e;
        }
        try {
            for (JsonElement account : call("GET", "external", null).getAsJsonArray("accounts"))
                all.add(account);
        } catch (ProtocolClient.ApiException e) {
            if (!e.code.equals("MINTAUTH_DISABLED")) throw e;
        }
        vault.update(
                data -> {
                    JsonObject entries = records(data);
                    Set<String> seen = new HashSet<>();
                    for (JsonElement element : all) {
                        JsonObject remote = element.getAsJsonObject();
                        String id = Json.string(remote, "id");
                        seen.add(id);
                        JsonObject old = entries.has(id) ? entries.getAsJsonObject(id) : null;
                        if (old == null && "OWNED".equals(Json.string(remote, "kind"))) {
                            String previousId = null;
                            for (Map.Entry<String, JsonElement> candidate : entries.entrySet()) {
                                JsonObject previous = candidate.getValue().getAsJsonObject();
                                if ("MANAGED".equals(Json.optional(previous, "source"))
                                        && Objects.equals(
                                                previous.get("context"), remote.get("context"))) {
                                    old = previous;
                                    previousId = candidate.getKey();
                                    break;
                                }
                            }
                            if (previousId != null) {
                                entries.remove(previousId);
                                if (previousId.equals(activeId)) activeId = id;
                            }
                        }
                        JsonObject updated =
                                AccountRecords.mergeRemote(
                                        old, remote, Json.string(auth, "device_id"));
                        entries.add(id, updated);
                    }
                    for (Map.Entry<String, JsonElement> entry : entries.entrySet()) {
                        JsonObject account = entry.getValue().getAsJsonObject();
                        if (!"LOCAL".equals(Json.optional(account, "source"))
                                && !seen.contains(entry.getKey())
                                && !"DELETED".equals(Json.optional(account, "status"))) {
                            account.addProperty("status", "UNAVAILABLE");
                            account.remove("ssid");
                        }
                    }
                    AccountRecords.applyCloudTombstones(data);
                    return null;
                });
        loadViews();
        clearRemovedActive();
        startEvents();
        status = "AutoMint accounts refreshed. Choose an account to play.";
    }

    public void importSsid(String ssid, boolean cloud) {
        trace.step(FlowDiagnostics.Step.ACCOUNT_IMPORT, FlowDiagnostics.Result.STARTED);
        final String token = ssid.trim();
        submit(
                StartupDiagnostics.Operation.IMPORT,
                () -> {
                    if (vault.header() == null) {
                        vault.unlock(null, false);
                        initializeKey();
                    } else vault.read();
                    JsonObject profile = api.profile(token), entry = new JsonObject();
                    String id = "local-" + Json.string(profile, "id").toLowerCase(Locale.ROOT);
                    entry.addProperty("id", id);
                    entry.addProperty("uuid", Json.string(profile, "id").toLowerCase(Locale.ROOT));
                    entry.addProperty("ign", Json.string(profile, "name"));
                    entry.addProperty("kind", "EXTERNAL");
                    entry.addProperty("source", "LOCAL");
                    entry.addProperty("status", "VALID");
                    entry.addProperty("revision", 1);
                    entry.addProperty("ssid", token);
                    if (cloud && linked) {
                        JsonObject body =
                                cloudImportBody(
                                        token,
                                        Json.string(profile, "id").toLowerCase(Locale.ROOT),
                                        true);
                        JsonObject remote =
                                call("POST", "external/import", body).getAsJsonObject("account");
                        id = Json.string(remote, "id");
                        entry = remote.deepCopy();
                        entry.addProperty("source", "CLOUD");
                        entry.addProperty("ssid", token);
                        entry.addProperty(
                                "grantId", Json.string(authorization(vault.read()), "device_id"));
                    }
                    final String key = id;
                    final JsonObject saved = entry;
                    vault.update(
                            data -> {
                                JsonObject prior =
                                        records(data).has(key)
                                                ? records(data).getAsJsonObject(key)
                                                : null;
                                if ("LOCAL".equals(Json.optional(saved, "source")))
                                    saved.addProperty(
                                            "revision",
                                            prior != null && prior.has("revision")
                                                    ? prior.get("revision").getAsInt() + 1
                                                    : 1);
                                records(data).add(key, saved);
                                return null;
                            });
                    loadViews();
                    trace.step(
                            FlowDiagnostics.Step.ACCOUNT_IMPORT, FlowDiagnostics.Result.SUCCEEDED);
                    status = "Account saved securely.";
                });
    }

    private JsonObject cloudImportBody(String token, String uuid, boolean deliberateReplacement)
            throws Exception {
        JsonObject body = Json.obj("ssid", token);
        for (Map.Entry<String, JsonElement> item : records(vault.read()).entrySet()) {
            JsonObject entry = item.getValue().getAsJsonObject();
            if ("CLOUD".equals(Json.optional(entry, "source"))
                    && uuid.equals(Json.string(entry, "uuid"))) {
                if ("DELETED".equals(Json.optional(entry, "status")) && !deliberateReplacement)
                    return null;
                body.addProperty("entryId", item.getKey());
                body.add("expectedRevision", entry.get("revision"));
                if ("DELETED".equals(Json.optional(entry, "status")))
                    body.addProperty("restoreDeleted", true);
                break;
            }
        }
        return body;
    }

    public void syncExisting() {
        trace.step(FlowDiagnostics.Step.ACCOUNT_SYNC, FlowDiagnostics.Result.QUEUED);
        submit(
                StartupDiagnostics.Operation.SYNC,
                () -> {
                    JsonObject data = vault.read();
                    final String syncGrant = Json.string(authorization(data), "device_id");
                    for (Map.Entry<String, JsonElement> item : records(data).entrySet()) {
                        JsonObject entry = item.getValue().getAsJsonObject();
                        if (!AccountRecords.needsSync(entry)) continue;
                        JsonObject importBody =
                                cloudImportBody(
                                        Json.string(entry, "ssid"),
                                        Json.string(entry, "uuid"),
                                        false);
                        if (importBody == null) continue;
                        JsonObject remote =
                                call("POST", "external/import", importBody)
                                        .getAsJsonObject("account");
                        String localId = item.getKey();
                        vault.update(
                                current -> {
                                    if (!current.has("authorization")
                                            || !syncGrant.equals(
                                                    Json.optional(
                                                            current.getAsJsonObject(
                                                                    "authorization"),
                                                            "device_id")))
                                        throw new ProtocolClient.ApiException(
                                                "EXTERNAL_CONFLICT", 409);
                                    if (!AccountRecords.saveCloudCopy(
                                            current, localId, entry, remote, syncGrant))
                                        throw new ProtocolClient.ApiException(
                                                "EXTERNAL_CONFLICT", 409);
                                    return null;
                                });
                    }
                    refreshLibrary();
                    trace.step(FlowDiagnostics.Step.ACCOUNT_SYNC, FlowDiagnostics.Result.SUCCEEDED);
                    status = "Existing local accounts synced.";
                });
    }

    public void remove(String id, boolean everywhere) {
        trace.step(
                everywhere
                        ? FlowDiagnostics.Step.ACCOUNT_DELETE_CLOUD
                        : FlowDiagnostics.Step.ACCOUNT_REMOVE_LOCAL,
                FlowDiagnostics.Result.QUEUED);
        submit(
                StartupDiagnostics.Operation.REMOVE,
                () -> {
                    JsonObject record = records(vault.read()).getAsJsonObject(id);
                    if (record == null) {
                        trace.step(
                                FlowDiagnostics.Step.ACCOUNT_REMOVE_LOCAL,
                                FlowDiagnostics.Result.EMPTY);
                        return;
                    }
                    selectionRevision.incrementAndGet();
                    if (everywhere && !"CLOUD".equals(Json.optional(record, "source"))) {
                        trace.step(
                                FlowDiagnostics.Step.ACCOUNT_DELETE_CLOUD,
                                FlowDiagnostics.Result.BLOCKED);
                        status = "Only cloud external entries can be deleted everywhere.";
                        return;
                    }
                    if (everywhere && "CLOUD".equals(Json.optional(record, "source"))) {
                        JsonObject body = Json.obj("action", "delete");
                        body.addProperty("entryId", id);
                        body.add("expectedRevision", record.get("revision"));
                        call("POST", "external/delete", body);
                    }
                    vault.update(
                            data -> {
                                JsonObject entry = records(data).getAsJsonObject(id);
                                if (entry != null) {
                                    AccountRecords.removeLocalCopy(entry, everywhere);
                                }
                                AccountRecords.applyCloudTombstones(data);
                                return null;
                            });
                    clearRemovedActive();
                    loadViews();
                    trace.step(
                            everywhere
                                    ? FlowDiagnostics.Step.ACCOUNT_DELETE_CLOUD
                                    : FlowDiagnostics.Step.ACCOUNT_REMOVE_LOCAL,
                            FlowDiagnostics.Result.SUCCEEDED);
                    status =
                            everywhere
                                    ? "Cloud entry deleted."
                                    : AccountRecords.onMint(record)
                                            ? "Local copy removed. This account is still available"
                                                    + " on AutoMint."
                                            : "Local account removed from this device.";
                });
    }

    public void restoreHidden() {
        trace.step(FlowDiagnostics.Step.ACCOUNT_RESTORE, FlowDiagnostics.Result.QUEUED);
        submit(
                StartupDiagnostics.Operation.RESTORE,
                () -> {
                    vault.update(
                            data -> {
                                for (Map.Entry<String, JsonElement> entry :
                                        records(data).entrySet())
                                    if (!"DELETED"
                                            .equals(
                                                    Json.optional(
                                                            entry.getValue().getAsJsonObject(),
                                                            "status")))
                                        entry.getValue().getAsJsonObject().remove("hidden");
                                return null;
                            });
                    loadViews();
                });
    }

    public void secureNewAccountOnWebsite() {
        if (!closed) accountWebsite.open();
    }

    public String secureWebsiteNotice() {
        return accountWebsite.message();
    }

    public boolean secureWebsiteOpening() {
        return accountWebsite.opening();
    }

    public boolean secureWebsiteAttempted() {
        return accountWebsite.attempted();
    }

    public void clearSecureWebsiteNotice() {
        accountWebsite.clear();
    }

    public void copySecureWebsiteLink() {
        game.onClient(
                () -> {
                    try {
                        game.copyWebsiteLink(AccountWebsiteAction.URL.toASCIIString());
                        accountWebsite.copied(true);
                    } catch (Exception | LinkageError ignored) {
                        accountWebsite.copied(false);
                    }
                });
    }

    public void secureOnWebsite() {
        submit(() -> game.openWebsite(new URI(ProtocolClient.ORIGIN + "/dashboard/accounts")));
    }

    public void select(String id, boolean move) {
        trace.step(FlowDiagnostics.Step.ACCOUNT_SELECT, FlowDiagnostics.Result.STARTED);
        if (id != null && id.equals(playingAccountId())) {
            trace.step(FlowDiagnostics.Step.ACCOUNT_SELECT, FlowDiagnostics.Result.SKIPPED);
            return;
        }
        AccountPreparation previous = preparation;
        if (previous != null) previous.cancel();
        final long revision = selectionRevision.incrementAndGet();
        final AccountPreparation attempt = new AccountPreparation(revision, id, trace);
        preparation = attempt;
        moveAccount = null;
        recoveryCount = 0;
        recoveryJoin = joinRevision.get();
        recoveryDestination = null;
        submit(
                StartupDiagnostics.Operation.SELECT,
                () -> {
                    try {
                        checkPreparation(revision);
                        attempt.update(
                                AccountPreparation.Phase.CHECKING, "Checking this account...");
                        JsonObject entry = records(vault.read()).getAsJsonObject(id);
                        prepare(
                                id,
                                move,
                                true,
                                revision,
                                entry != null && entry.has("rejectedTokenHash"),
                                true);
                        if (!attempt.snapshot().phase.terminal()
                                && attempt.snapshot().phase != AccountPreparation.Phase.APPLYING)
                            attempt.update(
                                    AccountPreparation.Phase.FAILED,
                                    "This preparation was interrupted. Choose the account again.");
                    } catch (CancellationException ignored) {
                        attempt.cancel();
                    } catch (Exception | LinkageError error) {
                        trace.failure(FlowDiagnostics.Step.ACCOUNT_PREPARE, error);
                        attempt.update(
                                AccountPreparation.Phase.FAILED,
                                AccountPreparation.failureMessage(error));
                        if (revision == selectionRevision.get()
                                || error instanceof ProtocolClient.ApiException
                                        && ((ProtocolClient.ApiException) error).authorityLost())
                            throw error;
                    }
                });
    }

    private JsonObject rsaKey() throws Exception {
        trace.step(FlowDiagnostics.Step.DELIVERY_KEY, FlowDiagnostics.Result.STARTED);
        try {
            JsonObject result = rsaKeyInternal();
            trace.step(FlowDiagnostics.Step.DELIVERY_KEY, FlowDiagnostics.Result.SUCCEEDED);
            return result;
        } catch (Exception | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.DELIVERY_KEY, error);
            throw error;
        }
    }

    private JsonObject rsaKeyInternal() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(3072);
        KeyPair pair = g.generateKeyPair();
        java.security.interfaces.RSAPublicKey pub =
                (java.security.interfaces.RSAPublicKey) pair.getPublic();
        byte[] modulus = pub.getModulus().toByteArray();
        if (modulus[0] == 0) modulus = Arrays.copyOfRange(modulus, 1, modulus.length);
        JsonObject result = Json.obj("privateKey", Crypto.b64(pair.getPrivate().getEncoded()));
        JsonObject publicKey = Json.obj("kty", "RSA");
        publicKey.addProperty("n", Crypto.b64(modulus));
        publicKey.addProperty("e", "AQAB");
        result.add("publicKey", publicKey);
        return result;
    }

    private JsonObject decrypt(JsonObject envelope, JsonObject rsa, JsonObject auth)
            throws Exception {
        trace.step(FlowDiagnostics.Step.ENVELOPE_DECRYPT, FlowDiagnostics.Result.STARTED);
        try {
            JsonObject result = decryptInternal(envelope, rsa, auth);
            trace.step(FlowDiagnostics.Step.ENVELOPE_DECRYPT, FlowDiagnostics.Result.SUCCEEDED);
            return result;
        } catch (Exception | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.ENVELOPE_DECRYPT, error);
            throw error;
        }
    }

    private JsonObject decryptInternal(JsonObject envelope, JsonObject rsa, JsonObject auth)
            throws Exception {
        JsonObject binding = new JsonObject();
        binding.addProperty("v", 1);
        binding.addProperty("dealId", Json.string(envelope, "bindingDealId"));
        binding.addProperty(
                "commandId",
                envelope.has("commandId")
                        ? Json.string(envelope, "commandId")
                        : Json.string(envelope, "id"));
        binding.addProperty("actorId", Json.string(auth, "subject"));
        binding.addProperty("purpose", "DELIVERY");
        binding.addProperty("credentialVersionId", Json.string(envelope, "credentialVersionId"));
        binding.add("reportId", JsonNull.INSTANCE);
        PrivateKey key =
                KeyFactory.getInstance("RSA")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Crypto.unb64(Json.string(rsa, "privateKey"))));
        JsonObject payload =
                Crypto.decryptEnvelope(
                        Json.string(envelope, "outputCiphertext"), key, Json.GSON.toJson(binding));
        if (!Json.string(payload, "deviceId").equals(Json.string(auth, "device_id"))
                || !Json.string(payload, "vaultGeneration")
                        .equals(Json.string(auth, "vault_generation")))
            throw new GeneralSecurityException("DELIVERY_BINDING");
        return payload;
    }

    private long time(JsonObject obj, String field) {
        String raw = Json.optional(obj, field);
        try {
            return raw == null ? 0 : Instant.parse(raw).toEpochMilli();
        } catch (Exception e) {
            return 0;
        }
    }

    private boolean offlineAllowed(JsonObject entry) throws Exception {
        try {
            boolean result = offlineAllowedInternal(entry);
            trace.state(
                    FlowDiagnostics.Step.OFFLINE_GRACE,
                    result ? FlowDiagnostics.Result.ALLOWED : FlowDiagnostics.Result.BLOCKED);
            return result;
        } catch (Exception | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.OFFLINE_GRACE, error);
            throw error;
        }
    }

    private boolean offlineAllowedInternal(JsonObject entry) throws Exception {
        JsonObject data = vault.read();
        long seen = data.has("lastSeenWallTime") ? data.get("lastSeenWallTime").getAsLong() : 0;
        return OfflineAllowance.persisted(
                System.currentTimeMillis(),
                time(entry, "checkedAt"),
                seen,
                time(entry, "offlineUntil"));
    }

    private JsonObject clearCachedManagedSession(String id) throws Exception {
        return vault.update(data -> {
            JsonObject record = records(data).getAsJsonObject(id);
            if (record == null) throw new IllegalArgumentException("ACCOUNT_UNAVAILABLE");
            record.addProperty("deviceRevision", UUID.randomUUID().toString());
            for (String field : new String[] { "ssid", "offlineUntil", "checkedAt", "tokenCheckedAt",
                    "providerCheckedAt", "knownExpiresAt", "sessionRevision" }) record.remove(field);
            return record.deepCopy();
        });
    }

    private static long revisionValue(JsonObject value, String key) {
        return value.has(key) && !value.get(key).isJsonNull() ? value.get(key).getAsLong() : 0L;
    }

    private void prepare(String id, boolean move, boolean install, long revision, boolean force)
            throws Exception {
        prepare(id, move, install, revision, force, false);
    }

    private void prepare(
            String id,
            boolean move,
            boolean install,
            long revision,
            boolean force,
            boolean userSelected)
            throws Exception {
        try {
            prepareAccount(id, move, install, revision, force, userSelected);
        } catch (ProtocolClient.ApiException e) {
            if (e.authorityLost() && !e.grantLost()) {
                try {
                    vault.update(
                            data -> {
                                JsonObject entry = records(data).getAsJsonObject(id);
                                if (entry != null) {
                                    entry.remove("ssid");
                                    entry.addProperty("status", "UNAVAILABLE");
                                }
                                return null;
                            });
                    loadViews();
                } catch (Exception ignored) {
                }
                if (id.equals(activeId)) clearActive("Account authorization ended.");
            }
            throw e;
        }
    }

    private void prepareAccount(
            String id,
            boolean move,
            boolean install,
            long revision,
            boolean force,
            boolean userSelected)
            throws Exception {
        checkPreparation(revision);
        final long expectedJoin = force ? recoveryJoin : -1;
        final String destination = force ? recoveryDestination : null;
        JsonObject data = vault.read(), entry = records(data).getAsJsonObject(id);
        if (entry == null
                || entry.has("hidden")
                || "DELETED".equals(Json.optional(entry, "status")))
            throw new IllegalArgumentException("ACCOUNT_UNAVAILABLE");
        if (AccountRecords.locallyRemoved(entry) && !userSelected) {
            if (id.equals(activeId))
                clearActive("Local account copy was removed from this device.");
            return;
        }
        entry = entry.deepCopy();
        final JsonElement startingRevision = entry.get("revision").deepCopy();
        if (entry.has("rejectedTokenHash") && !force)
            throw new ProtocolClient.ApiException("EXTERNAL_TOKEN_REJECTED", 422);
        String source = Json.string(entry, "source"), oldToken = Json.optional(entry, "ssid");
        trace.accountSource(source);
        final boolean requestCurrent = userSelected && "MANAGED".equals(source);
        JsonObject auth = source.equals("LOCAL") ? null : authorization(data);
        if (source.equals("MANAGED")) {
            preparationProgress(
                    revision,
                    userSelected,
                    AccountPreparation.Phase.CHECKING,
                    "Checking account access with AutoMint...");
            JsonObject body = new JsonObject();
            body.add("context", entry.get("context"));
            JsonObject authority;
            try {
                authority = call("POST", "authorization", body);
                if (authority.has("sessionRejected") && authority.get("sessionRejected").getAsBoolean()) {
                    oldToken = null;
                    boolean wasActive = id.equals(activeId);
                    if (wasActive) clearActive("Mint rejected this session. Select the account again to check it.");
                    entry = clearCachedManagedSession(id);
                    if (wasActive) return;
                }
                if (id.equals(activeId) && game.multiplayerWorldOpen()
                        && authority.has("multiplayer") && !authority.get("multiplayer").isJsonNull()
                        && !authority.get("multiplayer").getAsBoolean()) {
                    clearActive("Multiplayer was disabled for this account on AutoMint.");
                    return;
                }
                String stamp =
                        Json.string(authority, "credentialVersionId")
                                + "/"
                                + authority.get("ownershipEpoch")
                                + "/"
                                + authority.get("generationId")
                                + "/"
                                + authority.get("eligibilityRevision")
                                + "/"
                                + revisionValue(authority, "multiplayerRevision");
                if (!stamp.equals(Json.optional(entry, "authorityStamp"))
                        || revisionValue(authority, "sessionRevision") != revisionValue(entry, "sessionRevision")) {
                    oldToken = null;
                    entry.remove("ssid");
                    entry.remove("providerCheckedAt");
                }
                entry.addProperty("authorityStamp", stamp);
                entry.add("context", authority.get("context"));
                entry.add("offlineUntil", authority.get("offlineUntil"));
                entry.add("checkedAt", authority.get("checkedAt"));
                entry.add("transferPending", authority.get("transferPending"));
            } catch (IOException e) {
                if (e instanceof ProtocolClient.ApiException
                        && ((ProtocolClient.ApiException) e).authorityLost()) throw e;
                if (oldToken == null || !offlineAllowed(entry)) throw e;
                authority = null;
            }
            checkPreparation(revision);
            if (force
                    || requestCurrent && authority != null
                    || oldToken == null
                    || time(entry, "tokenCheckedAt") == 0
                    || System.currentTimeMillis() - time(entry, "tokenCheckedAt") >= 86400000L
                    || time(entry, "knownExpiresAt") > 0
                            && time(entry, "knownExpiresAt")
                                    <= System.currentTimeMillis() + 60000) {
                JsonObject rsa = rsaKey(), request = new JsonObject();
                request.addProperty("action", force ? "refresh" : "request");
                request.add("context", entry.get("context"));
                request.addProperty("idempotencyKey", UUID.randomUUID().toString());
                request.add("publicKey", rsa.get("publicKey"));
                checkPreparation(revision);
                preparationProgress(
                        revision,
                        userSelected,
                        AccountPreparation.Phase.PREPARING,
                        "Asking Mint for a playable session...");
                trace.step(FlowDiagnostics.Step.SESSION_REQUEST, FlowDiagnostics.Result.STARTED);
                JsonObject result = call("POST", "sessions", request).getAsJsonObject("result");
                trace.step(FlowDiagnostics.Step.SESSION_REQUEST, FlowDiagnostics.Result.SUCCEEDED);
                checkPreparation(revision);
                String requestId = Json.string(result, "id");
                rsa.addProperty("createdAt", System.currentTimeMillis());
                vault.update(
                        current -> {
                            if (!current.has("deliveries"))
                                current.add("deliveries", new JsonObject());
                            current.getAsJsonObject("deliveries").add(requestId, rsa);
                            return null;
                        });
                long deadline = System.currentTimeMillis() + 1200000L;
                while (Arrays.asList("QUEUED", "RUNNING").contains(Json.string(result, "state"))) {
                    checkPreparation(revision);
                    preparationProgress(
                            revision,
                            userSelected,
                            AccountPreparation.Phase.PREPARING,
                            "QUEUED".equals(Json.string(result, "state"))
                                    ? "Mint has queued your account check. You can cancel while"
                                            + " waiting."
                                    : "Mint is checking this account. You can cancel while"
                                            + " waiting.");
                    trace.state(
                            FlowDiagnostics.Step.SESSION_QUEUE,
                            "QUEUED".equals(Json.string(result, "state"))
                                    ? FlowDiagnostics.Result.QUEUED
                                    : FlowDiagnostics.Result.STARTED);
                    Thread.sleep(2000);
                    if (System.currentTimeMillis() > deadline)
                        throw new IOException("PREPARATION_EXPIRED");
                    checkPreparation(revision);
                    result = call("GET", "sessions/" + requestId, null).getAsJsonObject("result");
                }
                checkPreparation(revision);
                if (!"READY".equals(Json.string(result, "state")))
                    throw new ProtocolClient.ApiException(
                            Json.optional(result, "errorCode") == null
                                    ? "SESSION_CHECK_UNAVAILABLE"
                                    : Json.string(result, "errorCode"),
                            409);
                JsonObject payload = decrypt(result, rsa, auth);
                if (!Json.string(payload, "uuid").equals(Json.string(entry, "uuid")))
                    throw new GeneralSecurityException("IDENTITY_BINDING");
                if (time(payload, "providerCheckedAt") == 0)
                    throw new GeneralSecurityException("SESSION_CHECK_MISSING");
                entry.add("ssid", payload.get("ssid"));
                entry.add("tokenCheckedAt", payload.get("providerCheckedAt"));
                entry.add("knownExpiresAt", payload.get("knownExpiresAt"));
                vault.update(
                        current -> {
                            current.getAsJsonObject("deliveries").remove(requestId);
                            return null;
                        });
                checkPreparation(revision);
                JsonObject currentAuthority = call("POST", "authorization", body);
                if (authority != null) {
                    for (String field : new String[] { "uuid", "credentialVersionId", "ownershipEpoch",
                            "generationId", "eligibilityRevision", "multiplayerRevision", "multiplayer" }) {
                        if (!Objects.equals(authority.get(field), currentAuthority.get(field)))
                            throw new ProtocolClient.ApiException("SESSION_AUTHORITY_CHANGED", 409);
                    }
                }
                if (!Json.string(result, "credentialVersionId").equals(Json.string(currentAuthority, "credentialVersionId")))
                    throw new ProtocolClient.ApiException("SESSION_AUTHORITY_CHANGED", 409);
                entry.add("offlineUntil", currentAuthority.get("offlineUntil"));
                entry.add("checkedAt", currentAuthority.get("checkedAt"));
                if (payload.has("multiplayerRevision")
                        && (!Objects.equals(payload.get("multiplayerRevision"), currentAuthority.get("multiplayerRevision"))
                                || !Objects.equals(payload.get("sessionRevision"), currentAuthority.get("sessionRevision"))))
                    throw new ProtocolClient.ApiException("SESSION_AUTHORITY_CHANGED", 409);
                entry.add("sessionRevision", payload.get("sessionRevision"));
                entry.add("multiplayerRevision", payload.get("multiplayerRevision"));
                game.logDiagnostic("[MintAuth] Session result="
                        + (payload.has("reused") && payload.get("reused").getAsBoolean() ? "REUSED" : "CHECKED")
                        + " revision=" + revisionValue(payload, "sessionRevision")
                        + " check_age_ms=" + Math.max(0L, System.currentTimeMillis() - time(payload, "providerCheckedAt")));

            }
        } else if (source.equals("CLOUD")) {
            try {
                JsonObject authority =
                        call("POST", "external/authorization", Json.obj("entryId", id));
                boolean same = Objects.equals(authority.get("revision"), entry.get("revision"));
                entry.add("offlineUntil", authority.get("offlineUntil"));
                entry.addProperty("checkedAt", Instant.now().toString());
                checkPreparation(revision);
                if (oldToken == null || !same) {
                    JsonObject rsa = rsaKey(), body = Json.obj("entryId", id);
                    body.add("publicKey", rsa.get("publicKey"));
                    JsonObject envelope = call("POST", "external/delivery", body),
                            payload = decrypt(envelope, rsa, auth);
                    if (!Json.string(payload, "uuid").equals(Json.string(entry, "uuid")))
                        throw new GeneralSecurityException("IDENTITY_BINDING");
                    entry.add("ssid", payload.get("ssid"));
                    entry.add("revision", payload.get("revision"));
                    entry.add("knownExpiresAt", payload.get("knownExpiresAt"));
                }
            } catch (IOException e) {
                if (e instanceof ProtocolClient.ApiException
                        && ((ProtocolClient.ApiException) e).authorityLost()) throw e;
                if (oldToken == null || !offlineAllowed(entry)) throw e;
            }
        } else {
            try {
                api.profile(Json.string(entry, "ssid"));
            } catch (IOException e) {
                if (e instanceof ProtocolClient.ApiException
                        && ((ProtocolClient.ApiException) e).code.equals("EXTERNAL_TOKEN_REJECTED"))
                    throw e;
            }
        }
        if (time(entry, "knownExpiresAt") > 0
                && time(entry, "knownExpiresAt") <= System.currentTimeMillis())
            throw new ProtocolClient.ApiException("EXTERNAL_TOKEN_REJECTED", 422);
        if (entry.has("rejectedTokenHash")
                && Json.string(entry, "rejectedTokenHash")
                        .equals(Crypto.tokenHash(Json.string(entry, "ssid")))) {
            if (force) {
                status =
                        "The provider returned the same rejected SSID. Automatic recovery stopped.";
                preparationProgress(
                        revision, userSelected, AccountPreparation.Phase.FAILED, status);
                return;
            }
            throw new ProtocolClient.ApiException("EXTERNAL_TOKEN_REJECTED", 422);
        } else {
            entry.remove("rejectedTokenHash");
            entry.addProperty("status", "AVAILABLE");
        }
        checkPreparation(revision);
        final JsonObject updated = entry;
        if (!vault.update(
                current ->
                        revision == selectionRevision.get()
                                && !closed
                                && AccountRecords.commitPrepared(
                                        current, id, startingRevision, updated, userSelected))) {
            preparationProgress(
                    revision,
                    userSelected,
                    AccountPreparation.Phase.FAILED,
                    "This saved account changed during preparation. Select it again.");
            return;
        }
        loadViews();
        if (!install) {
            if (id.equals(activeId)) {
                activeOfflineUntil = time(entry, "offlineUntil");
                activeOfflineDeadline =
                        OfflineAllowance.deadline(
                                System.currentTimeMillis(), System.nanoTime(), activeOfflineUntil);
                activeKnownExpiry = time(entry, "knownExpiresAt");
                pendingApply =
                        !new GameBridge.Identity(
                                        Json.string(entry, "uuid"),
                                        Json.string(entry, "ign"),
                                        Json.string(entry, "ssid"))
                                .fingerprint()
                                .equals(activeFingerprint);
            }
            if (pendingApply)
                status = "Replacement ready; it will be applied after leaving the game.";
            return;
        }
        if (revision != selectionRevision.get()) return;
        if (force && expectedJoin != joinRevision.get()) return;
        if (force) {
            long waitUntil = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (game.worldOpen()
                    && System.nanoTime() < waitUntil
                    && revision == selectionRevision.get()) Thread.sleep(100);
        }
        if (game.worldOpen()) {
            preparationProgress(
                    revision,
                    userSelected,
                    AccountPreparation.Phase.FAILED,
                    "Leave the current world or server, then choose this account again.");
            return;
        }
        String uuid = Json.string(entry, "uuid");
        final GameBridge.Identity identity =
                new GameBridge.Identity(
                        uuid, Json.string(entry, "ign"), Json.string(entry, "ssid"));
        if (force
                && oldToken != null
                && Crypto.tokenHash(oldToken).equals(Crypto.tokenHash(identity.token()))) {
            status = "The provider returned the same rejected SSID. Try again later.";
            preparationProgress(revision, userSelected, AccountPreparation.Phase.FAILED, status);
            return;
        }
        checkPreparation(revision);
        preparationProgress(
                revision,
                userSelected,
                AccountPreparation.Phase.PREPARING,
                "Preparing your Minecraft profile...");
        MultiplayerAccess checkedAccess = MultiplayerAccess.UNKNOWN;
        try {
            checkedAccess = api.multiplayerAccess(identity.token());
        } catch (ProtocolClient.ApiException rejected) {
            if (rejected.code.equals("EXTERNAL_TOKEN_REJECTED")) throw rejected;
        } catch (IOException | RuntimeException unavailable) {
        }
        final MultiplayerAccess access = checkedAccess;
        checkPreparation(revision);
        trace.step(FlowDiagnostics.Step.IDENTITY_PREPARE, FlowDiagnostics.Result.STARTED);
        final Object prepared = game.prepare(identity);
        trace.step(FlowDiagnostics.Step.IDENTITY_PREPARE, FlowDiagnostics.Result.SUCCEEDED);
        try {
            if (revision != selectionRevision.get() || game.worldOpen() || vault.isWiped()) {
                closePrepared(prepared);
                return;
            }
            if (!lease.acquire(uuid)) {
                if (!move) {
                    moveAccount = id;
                    preparationProgress(
                            revision,
                            userSelected,
                            AccountPreparation.Phase.MOVE,
                            "This account is active in another local instance. Choose Move play to"
                                    + " continue.");
                    closePrepared(prepared);
                    return;
                }
                lease.requestMove(uuid);
                long end = System.currentTimeMillis() + 10000;
                while (!lease.acquire(uuid) && System.currentTimeMillis() < end) {
                    checkPreparation(revision);
                    Thread.sleep(200);
                }
                checkPreparation(revision);
                if (!lease.acquire(uuid)) throw new IOException("INSTANCE_STILL_ACTIVE");
            }
        } catch (Exception error) {
            closePrepared(prepared);
            throw error;
        }
        moveAccount = null;
        final String warning = game.preparationWarning(prepared);
        final long offlineUntil = time(entry, "offlineUntil"),
                knownExpiry = time(entry, "knownExpiresAt");
        preparationProgress(
                revision,
                userSelected,
                AccountPreparation.Phase.APPLYING,
                "Switching your Minecraft account...");
        trace.step(FlowDiagnostics.Step.IDENTITY_APPLY, FlowDiagnostics.Result.QUEUED);
        final boolean transferWarning =
                entry.has("transferPending") && entry.get("transferPending").getAsBoolean();
        game.onClient(
                () -> {
                    if (revision != selectionRevision.get()
                            || vault.isWiped()
                            || game.worldOpen()
                            || force && expectedJoin != joinRevision.get()) {
                        closePrepared(prepared);
                        preparationProgress(
                                revision,
                                userSelected,
                                AccountPreparation.Phase.FAILED,
                                "Minecraft changed before the switch finished. Leave the game and"
                                        + " choose the account again.");
                        return;
                    }
                    try {
                        final boolean previouslyUnsafe = identityUnsafe;
                        identityUnsafe = true;
                        trace.step(
                                FlowDiagnostics.Step.IDENTITY_APPLY,
                                FlowDiagnostics.Result.STARTED);
                        boolean installed =
                                vault.inspect(
                                        current -> {
                                            if (revision != selectionRevision.get()
                                                    || closed
                                                    || game.worldOpen()
                                                    || !AccountRecords.matchesPrepared(
                                                            current, id, updated)) return false;
                                            game.installPrepared(identity, prepared);
                                            return true;
                                        });
                        if (!installed) {
                            identityUnsafe = previouslyUnsafe;
                            closePrepared(prepared);
                            preparationProgress(
                                    revision,
                                    userSelected,
                                    AccountPreparation.Phase.FAILED,
                                    "This sign-in changed before it was applied. Choose the account"
                                            + " again.");
                            return;
                        }
                        trace.step(
                                FlowDiagnostics.Step.IDENTITY_APPLY,
                                FlowDiagnostics.Result.SUCCEEDED);
                        activeId = id;
                        activeFingerprint = identity.fingerprint();
                        activeSource = source;
                        activeMultiplayerAccess = access;
                        activeRejected = false;
                        identityUnsafe = false;
                        activeOfflineUntil = offlineUntil;
                        activeOfflineDeadline =
                                OfflineAllowance.deadline(
                                        System.currentTimeMillis(),
                                        System.nanoTime(),
                                        offlineUntil);
                        activeKnownExpiry = knownExpiry;
                        status =
                                "Playing as "
                                        + identity.ign
                                        + (transferWarning
                                                ? ". Pending transfer: playing exposes this account"
                                                        + " to your session."
                                                : "");
                        if (access.restriction() != null) status += ". " + access.restriction();
                        if (warning != null) status += ". " + warning;
                        preparationProgress(
                                revision, userSelected, AccountPreparation.Phase.READY, status);
                        if (force && destination != null && expectedJoin == joinRevision.get()) {
                            automaticReconnect = true;
                            trace.step(
                                    FlowDiagnostics.Step.RECONNECT, FlowDiagnostics.Result.STARTED);
                            try {
                                game.connect(destination);
                                trace.step(
                                        FlowDiagnostics.Step.RECONNECT,
                                        FlowDiagnostics.Result.SUCCEEDED);
                            } finally {
                                automaticReconnect = false;
                            }
                        }
                    } catch (Exception error) {
                        trace.failure(FlowDiagnostics.Step.IDENTITY_APPLY, error);
                        closePrepared(prepared);
                        preparationProgress(
                                revision,
                                userSelected,
                                AccountPreparation.Phase.FAILED,
                                "Minecraft could not switch accounts. Your launcher account will be"
                                        + " restored; try again.");
                        activeId = null;
                        activeFingerprint = null;
                        lease.close();
                        try {
                            game.restoreLauncher();
                            identityUnsafe = false;
                            status = "Switch failed; launcher identity restored.";
                        } catch (Exception restoreError) {
                            trace.failure(FlowDiagnostics.Step.LAUNCHER_RESTORE, restoreError);
                            status =
                                    "Identity restoration failed. Restart Minecraft from the"
                                            + " launcher.";
                        }
                    }
                });
    }

    private void closePrepared(Object value) {
        if (value instanceof AutoCloseable)
            try {
                ((AutoCloseable) value).close();
            } catch (Exception ignored) {
            }
    }

    public void rememberDestination(String destination) {
        trace.step(FlowDiagnostics.Step.DESTINATION_CHANGE, FlowDiagnostics.Result.SUCCEEDED);
        if (!automaticReconnect && destination != null && destination.length() <= 512) {
            lastDestination = destination;
            recoveryCount = 0;
            joinRevision.incrementAndGet();
        }
    }

    public void invalidSession(String rejectedFingerprint) {
        trace.step(FlowDiagnostics.Step.AUTHENTICATION_REJECTED, FlowDiagnostics.Result.STARTED);
        if (activeId == null || !Objects.equals(activeFingerprint, rejectedFingerprint)) return;
        invalidSession();
    }

    public void invalidSession() {
        if (activeId == null) return;
        activeRejected = true;
        final String selected = activeId;
        final String rejected = activeFingerprint;
        io.execute(
                () -> {
                    try {
                        vault.update(
                                data -> {
                                    JsonObject entry = records(data).getAsJsonObject(selected);
                                    if (entry != null
                                            && entry.has("ssid")
                                            && rejected != null
                                            && rejected.endsWith(
                                                    ":"
                                                            + Crypto.tokenHash(
                                                                    Json.string(entry, "ssid")))) {
                                        entry.addProperty(
                                                "rejectedTokenHash",
                                                Crypto.tokenHash(Json.string(entry, "ssid")));
                                        entry.addProperty("status", "EXPIRED_REJECTED");
                                    }
                                    return null;
                                });
                        loadViews();
                    } catch (Exception ignored) {
                    }
                });
        if (recoveryCount++ > 0) {
            trace.step(FlowDiagnostics.Step.RECOVERY, FlowDiagnostics.Result.BLOCKED);
            status = "Expired / rejected session. Automatic recovery stopped.";
            return;
        }
        trace.step(FlowDiagnostics.Step.RECOVERY, FlowDiagnostics.Result.STARTED);
        recoveryJoin = joinRevision.get();
        recoveryDestination = lastDestination;
        final long revision = selectionRevision.get();
        submit(
                () -> {
                    JsonObject entry = records(vault.read()).getAsJsonObject(selected);
                    if (entry == null) return;
                    if (!"MANAGED".equals(Json.string(entry, "source"))) {
                        status =
                                "Expired / rejected SSID. Paste a replacement or secure it with"
                                        + " Mint.";
                        return;
                    }
                    prepare(selected, false, true, revision, true);
                });
    }

    public boolean allowJoin() {
        try {
            boolean result = allowJoinInternal();
            trace.state(
                    FlowDiagnostics.Step.JOIN_GATE,
                    result ? FlowDiagnostics.Result.ALLOWED : FlowDiagnostics.Result.BLOCKED);
            return result;
        } catch (RuntimeException | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.JOIN_GATE, error);
            throw error;
        }
    }

    private boolean allowJoinInternal() {
        if (identityUnsafe) return false;
        if (activeId == null) return true;
        long now = System.currentTimeMillis();
        return !activeRejected
                && !vault.isWiped()
                && (activeKnownExpiry == 0 || activeKnownExpiry > now)
                && ("LOCAL".equals(activeSource)
                        || activeOfflineUntil > now && System.nanoTime() < activeOfflineDeadline);
    }

    public boolean checkBeforeAuthentication(String fingerprint) {
        return checkBeforeAuthentication(fingerprint, false);
    }

    public boolean checkBeforeServerJoin(String fingerprint) {
        return checkBeforeAuthentication(fingerprint, true);
    }

    private boolean checkBeforeAuthentication(String fingerprint, boolean serverJoin) {
        try {
            boolean result = checkBeforeAuthenticationInternal(fingerprint, serverJoin);
            trace.state(
                    FlowDiagnostics.Step.JOIN_AUTH,
                    result ? FlowDiagnostics.Result.ALLOWED : FlowDiagnostics.Result.BLOCKED);
            return result;
        } catch (RuntimeException | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.JOIN_AUTH, error);
            throw error;
        }
    }

    private boolean checkBeforeAuthenticationInternal(String fingerprint, boolean serverJoin) {
        if (identityUnsafe) return false;
        final String selected = activeId;
        if (selected == null || !Objects.equals(activeFingerprint, fingerprint)) return true;
        try {
            checkCleanup();
            if (!Objects.equals(selected, activeId)
                    || !Objects.equals(fingerprint, activeFingerprint)) return false;
            JsonObject data = vault.read(), entry = records(data).getAsJsonObject(selected);
            if (entry == null || entry.has("hidden") || AccountRecords.locallyRemoved(entry)) {
                clearActive("Local account copy was removed from this device.");
                return false;
            }
            if (serverJoin) {
                MultiplayerAccess fresh = MultiplayerAccess.UNKNOWN;
                try {
                    fresh = api.multiplayerAccess(Json.string(entry, "ssid"));
                } catch (ProtocolClient.ApiException rejected) {
                    if (rejected.code.equals("EXTERNAL_TOKEN_REJECTED")) throw rejected;
                } catch (IOException | RuntimeException unavailable) {
                }
                if (!Objects.equals(selected, activeId)
                        || !Objects.equals(fingerprint, activeFingerprint)) return false;
                if (fresh != MultiplayerAccess.UNKNOWN) {
                    boolean wasRestricted = activeMultiplayerAccess.restriction() != null;
                    activeMultiplayerAccess = fresh;
                    if (fresh == MultiplayerAccess.ALLOWED && wasRestricted)
                        status = "Multiplayer is now available for this account.";
                }
            }
            String source = Json.string(entry, "source");
            if (source.equals("LOCAL"))
                return (!serverJoin || multiplayerPermitsJoin()) && allowJoin();
            JsonObject body = new JsonObject();
            JsonObject authority;
            if (source.equals("MANAGED")) {
                body.add("context", entry.get("context"));
                authority = call("POST", "authorization", body);
                if (authority.has("sessionRejected") && authority.get("sessionRejected").getAsBoolean()) {
                    clearActive("Mint rejected this session. Select the account again to check it.");
                    clearCachedManagedSession(selected);
                    return false;
                }
                if (authority.has("multiplayer")
                        && !authority.get("multiplayer").isJsonNull()
                        && !authority.get("multiplayer").getAsBoolean()) {
                    status =
                            "Multiplayer is unavailable for this account. Singleplayer remains"
                                    + " available.";
                    return false;
                }
                String stamp =
                        Json.string(authority, "credentialVersionId")
                                + "/"
                                + authority.get("ownershipEpoch")
                                + "/"
                                + authority.get("generationId")
                                + "/"
                                + authority.get("eligibilityRevision")
                                + "/"
                                + revisionValue(authority, "multiplayerRevision");
                if (!stamp.equals(Json.optional(entry, "authorityStamp"))) {
                    clearActive(
                            "Account authority changed. Select the account again to prepare its"
                                    + " current session.");
                    return false;
                }
            } else {
                body.addProperty("entryId", selected);
                authority = call("POST", "external/authorization", body);
                if (!Objects.equals(authority.get("revision"), entry.get("revision"))) {
                    clearActive("Saved SSID changed. Select the account again.");
                    return false;
                }
            }
            if (!Objects.equals(selected, activeId)
                    || !Objects.equals(fingerprint, activeFingerprint)) return false;
            long until = time(authority, "offlineUntil");
            vault.update(
                    current -> {
                        JsonObject saved = records(current).getAsJsonObject(selected);
                        if (saved != null) {
                            saved.add("offlineUntil", authority.get("offlineUntil"));
                            saved.add("checkedAt", authority.get("checkedAt"));
                        }
                        return null;
                    });
            activeOfflineUntil = until;
            activeOfflineDeadline =
                    OfflineAllowance.deadline(System.currentTimeMillis(), System.nanoTime(), until);
            return (!serverJoin || multiplayerPermitsJoin()) && allowJoin();
        } catch (ProtocolClient.ApiException error) {
            trace.failure(FlowDiagnostics.Step.JOIN_AUTH, error);
            if (error.code.equals("EXTERNAL_TOKEN_REJECTED")) {
                invalidSession(fingerprint);
                return false;
            }
            if (error.grantLost()) {
                clearLinkedUse();
                return false;
            }
            if (error.authorityLost()) {
                clearActive("Account authorization ended.");
                return false;
            }
            return (!serverJoin || multiplayerPermitsJoin()) && allowJoin();
        } catch (IOException error) {
            trace.failure(FlowDiagnostics.Step.JOIN_AUTH, error);
            return (!serverJoin || multiplayerPermitsJoin()) && allowJoin();
        } catch (Exception | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.JOIN_AUTH, error);
            return false;
        }
    }

    private boolean multiplayerPermitsJoin() {
        String issue = multiplayerIssue();
        if (issue == null) return true;
        status = issue;
        trace.multiplayer(activeMultiplayerAccess);
        return false;
    }

    public void restoreLauncher() {
        trace.step(FlowDiagnostics.Step.LAUNCHER_RESTORE, FlowDiagnostics.Result.QUEUED);
        selectionRevision.incrementAndGet();
        game.onClient(
                () -> {
                    if (game.worldOpen()) {
                        trace.step(
                                FlowDiagnostics.Step.LAUNCHER_RESTORE,
                                FlowDiagnostics.Result.BLOCKED);
                        status = "Leave the current game before restoring the launcher account.";
                        return;
                    }
                    try {
                        game.restoreLauncher();
                        trace.step(
                                FlowDiagnostics.Step.LAUNCHER_RESTORE,
                                FlowDiagnostics.Result.SUCCEEDED);
                        identityUnsafe = false;
                        activeId = null;
                        activeFingerprint = null;
                        lease.close();
                        status =
                                "Launcher identity restored. Reauthenticate in the launcher if its"
                                        + " session has expired.";
                    } catch (Exception e) {
                        trace.failure(FlowDiagnostics.Step.LAUNCHER_RESTORE, e);
                        identityUnsafe = true;
                        status = "Restart Minecraft from your launcher to restore its account.";
                    }
                });
    }

    void loadSavedAccounts() throws Exception {
        initializeKey();
        loadViews();
    }

    private void clearRemovedActive() throws Exception {
        String selected = activeId;
        if (selected == null) return;
        JsonObject entry = records(vault.read()).getAsJsonObject(selected);
        if (!AccountRecords.canRestore(entry) && selected.equals(activeId))
            clearActive("The active sign-in was removed from this device.");
    }

    private void clearActive(String reason) {
        trace.step(FlowDiagnostics.Step.IDENTITY_CLEAR, FlowDiagnostics.Result.STARTED);
        selectionRevision.incrementAndGet();
        boolean hadMint = activeId != null;
        if (hadMint) identityUnsafe = true;
        activeId = null;
        activeFingerprint = null;
        lease.close();
        if (hadMint)
            game.onClient(
                    () ->
                            game.leaveWorld(
                                    reason,
                                    () -> {
                                        try {
                                            game.restoreLauncher();
                                            identityUnsafe = false;
                                        } catch (Exception ignored) {
                                        }
                                    }));
    }

    private void clearLinkedUse() {
        trace.step(FlowDiagnostics.Step.AUTHORITY_LOST, FlowDiagnostics.Result.STARTED);
        try {
            vault.update(
                    data -> {
                        data.remove("authorization");
                        for (Map.Entry<String, JsonElement> item : records(data).entrySet())
                            if (!"LOCAL"
                                    .equals(
                                            Json.optional(
                                                    item.getValue().getAsJsonObject(), "source")))
                                item.getValue().getAsJsonObject().remove("ssid");
                        return null;
                    });
        } catch (Exception ignored) {
        }
        linked = false;
        reportLocalState();
        if (activeId != null)
            try {
                JsonObject entry = records(vault.read()).getAsJsonObject(activeId);
                if (entry == null || !"LOCAL".equals(Json.optional(entry, "source")))
                    clearActive("Mint authorization ended.");
            } catch (Exception e) {
                clearActive("Mint authorization ended.");
            }
    }

    public void unlinkAndClear() {
        trace.step(FlowDiagnostics.Step.REVOKE_REQUEST, FlowDiagnostics.Result.QUEUED);
        submit(
                StartupDiagnostics.Operation.REVOKE,
                () -> {
                    call("POST", "revoke", new JsonObject());
                    checkCleanup();
                });
    }

    public void clearThisDevice() {
        trace.step(FlowDiagnostics.Step.VAULT_WIPE, FlowDiagnostics.Result.QUEUED);
        submit(
                StartupDiagnostics.Operation.CLEAR,
                () -> {
                    vault.clearLocally();
                    storageIssue = "VAULT_REVOKED";
                    linked = false;
                    diagnostics.local(StartupDiagnostics.Storage.CLEARED, null, false);
                    views = Collections.emptyList();
                    clearActive("MintAuth credentials cleared on this device.");
                    if (signer instanceof AutoCloseable) ((AutoCloseable) signer).close();
                    signer = null;
                    status =
                            (vault.cleanupPartial()
                                            ? "Local vault cleared; native key cleanup is"
                                                    + " incomplete. "
                                            : "Local credentials cleared. ")
                                    + "Use website Security to revoke server access as well.";
                });
    }

    private void checkCleanup() throws Exception {
        trace.step(FlowDiagnostics.Step.CLEANUP_CHECK, FlowDiagnostics.Result.STARTED);
        JsonObject current = vault.header();
        if (current == null) return;
        List<JsonObject> targets = new ArrayList<>();
        if (current.has("previousEnrollment"))
            targets.add(current.getAsJsonObject("previousEnrollment"));
        if (current.has("deviceId")) targets.add(current);
        JsonObject own = enrollmentHeader;
        if (own != null
                && own.has("deviceId")
                && !Json.string(own, "generation").equals(Json.string(current, "generation"))
                && targets.stream()
                        .noneMatch(
                                t ->
                                        Json.string(t, "generation")
                                                .equals(Json.string(own, "generation"))))
            targets.add(own);
        for (JsonObject header : targets) checkCleanupTarget(header, current);
    }

    private void checkCleanupTarget(JsonObject header, JsonObject current) throws Exception {
        JsonObject response =
                api.request(
                        "GET",
                        "cleanup?locator=" + Json.string(header, "cleanupLocator"),
                        null,
                        null,
                        null);
        String signed = Json.optional(response, "command");
        if (signed == null) return;
        JsonArray keys = api.request("GET", "keys", null, null, null).getAsJsonArray("keys");
        JsonObject command =
                CleanupVerifier.verify(
                        signed,
                        keys,
                        Json.string(header, "deviceId"),
                        Json.string(header, "generation"),
                        trace);
        String commandId = Json.string(command, "commandId"),
                generation = Json.string(header, "generation");
        trace.step(FlowDiagnostics.Step.CLEANUP_APPLY, FlowDiagnostics.Result.STARTED);
        vault.clear(command);
        trace.step(FlowDiagnostics.Step.CLEANUP_APPLY, FlowDiagnostics.Result.SUCCEEDED);
        boolean affectsThis =
                Objects.equals(
                                enrollmentHeader == null
                                        ? null
                                        : Json.optional(enrollmentHeader, "generation"),
                                generation)
                        || vault.isWiped();
        if (affectsThis && !commandId.equals(completedCleanup)) {
            completedCleanup = commandId;
            storageIssue = "VAULT_REVOKED";
            linked = false;
            diagnostics.local(StartupDiagnostics.Storage.CLEARED, null, false);
            views = Collections.emptyList();
            Crypto.Signer oldSigner = signer;
            signer = null;
            if (oldSigner instanceof AutoCloseable)
                try {
                    ((AutoCloseable) oldSigner).close();
                } catch (Exception ignored) {
                }
            boolean active = activeId != null;
            clearActive("MintAuth was revoked. Clearing saved credentials.");
            if (active)
                game.onClient(
                        () ->
                                game.leaveWorld(
                                        "MintAuth device cleared",
                                        () -> {
                                            try {
                                                instances.report(
                                                        generation,
                                                        !identityUnsafe && !vault.cleanupPartial());
                                            } catch (Exception ignored) {
                                            }
                                        }));
            else instances.report(generation, !identityUnsafe && !vault.cleanupPartial());
        }
        JsonObject receipt = Json.obj("locator", Json.string(header, "cleanupLocator"));
        receipt.addProperty("receipt", Json.string(header, "cleanupReceipt"));
        receipt.addProperty("commandId", Json.string(command, "commandId"));
        receipt.addProperty("vaultGeneration", Json.string(header, "generation"));
        boolean complete = instances.allReported(generation);
        receipt.addProperty("state", complete ? "CLEARED" : "PARTIAL");
        api.request("POST", "cleanup/receipt", receipt, null, null);
        if (affectsThis)
            status =
                    complete
                            ? "Access revoked. This device reports local credentials cleared."
                            : "Access revoked. Vault cleared; another instance has not confirmed"
                                    + " cleanup.";
    }

    private void startEvents() {
        if (streamRunning || closed) return;
        streamRunning = true;
        events.execute(
                () -> {
                    try {
                        while (!closed && linked) {
                            JsonObject auth = authorization(vault.read());
                            api.events(
                                    Json.string(auth, "access_token"),
                                    signer,
                                    (type, body) -> {
                                        if (type.equals("cleanup"))
                                            cleanup.execute(
                                                    () -> {
                                                        try {
                                                            checkCleanup();
                                                        } catch (Exception ignored) {
                                                        }
                                                    });
                                    });
                        }
                    } catch (Exception ignored) {
                    } finally {
                        streamRunning = false;
                    }
                });
    }

    private void maintenance() {
        if (closed) return;
        long now = System.currentTimeMillis();
        try {
            if (automaticUpdates
                    && linked
                    && updates != null
                    && now - lastUpdateCheck >= 4L * 60 * 60 * 1000) checkUpdates();
            if (signer == null || vault.isWiped()) return;
            if (now >= nextPairPoll) {
                nextPairPoll = now + 5000;
                pollPairing();
            }
            if (linked && now - lastHeartbeat >= 30000) {
                lastHeartbeat = now;
                vault.update(
                        data -> {
                            long previous =
                                    data.has("lastSeenWallTime")
                                            ? data.get("lastSeenWallTime").getAsLong()
                                            : 0;
                            data.addProperty("lastSeenWallTime", Math.max(previous, now));
                            if (data.has("deliveries")) {
                                Iterator<Map.Entry<String, JsonElement>> pending =
                                        data.getAsJsonObject("deliveries").entrySet().iterator();
                                while (pending.hasNext()) {
                                    JsonObject request =
                                            pending.next().getValue().getAsJsonObject();
                                    if (!request.has("createdAt")
                                            || now - request.get("createdAt").getAsLong() > 1200000)
                                        pending.remove();
                                }
                            }
                            return null;
                        });
                call("GET", "authorization", null);
                if (activeId != null) {
                    JsonObject entry = records(vault.read()).getAsJsonObject(activeId);
                    if (entry != null && !"LOCAL".equals(Json.optional(entry, "source")))
                        prepare(activeId, false, false, selectionRevision.get(), false);
                }
                startEvents();
            }
        } catch (Exception | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.MAINTENANCE, error);
            failure(error);
        }
    }

    public void tick() {
        long now = System.currentTimeMillis();
        if (now - lastLocalCheck < 500) return;
        lastLocalCheck = now;
        if (activeId != null && vault.isWiped()) {
            clearActive("MintAuth credentials were cleared by another instance.");
            return;
        }
        if (activeId != null && lease.moveRequested()) {
            clearActive("Play moved to another Minecraft instance.");
            return;
        }
        if (activeFingerprint != null && !activeFingerprint.equals(game.currentFingerprint())) {
            trace.step(
                    FlowDiagnostics.Step.IDENTITY_EXTERNAL_CHANGE,
                    FlowDiagnostics.Result.SUCCEEDED);
            selectionRevision.incrementAndGet();
            activeId = null;
            activeFingerprint = null;
            lease.close();
            status =
                    "Another mod changed the active identity. Select an account again to resume"
                            + " MintAuth.";
            return;
        }
        if (pendingApply && activeId != null && !game.worldOpen()) {
            pendingApply = false;
            final String id = activeId;
            final long revision = selectionRevision.get();
            submit(() -> prepare(id, false, true, revision, false));
        }
    }

    private static String platform() {
        return RuntimePlatform.identifier(
                System.getProperty("os.name"), System.getProperty("os.arch"));
    }

    @Override
    public void close() {
        trace.step(FlowDiagnostics.Step.RUNTIME_CLOSE, FlowDiagnostics.Result.STARTED);
        closed = true;
        io.shutdownNow();
        updateIo.shutdownNow();
        pairingWebsite.clear();
        browserIo.shutdownNow();
        events.shutdownNow();
        cleanup.shutdownNow();
        lease.close();
        vault.close();
        if (enrollmentHeader != null)
            try {
                instances.report(Json.string(enrollmentHeader, "generation"), true);
            } catch (Exception ignored) {
            }
        if (signer instanceof AutoCloseable)
            try {
                ((AutoCloseable) signer).close();
            } catch (Exception ignored) {
            }
    }
}
