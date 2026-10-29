// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import com.google.gson.JsonObject;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

final class FlowDiagnostics {
    enum Step {
        RUNTIME_START,
        ACCOUNT_IMPORT,
        ACCOUNT_SYNC,
        ACCOUNT_REMOVE_LOCAL,
        ACCOUNT_DELETE_CLOUD,
        ACCOUNT_RESTORE,
        ACCOUNT_SELECT,
        ACCOUNT_SOURCE,
        ACCOUNT_PREPARE,
        PREPARATION_PHASE,
        SESSION_REQUEST,
        SESSION_FRESH_CHECK,
        SESSION_QUEUE,
        DELIVERY_KEY,
        ENVELOPE_DECRYPT,
        OFFLINE_GRACE,
        IDENTITY_PREPARE,
        IDENTITY_APPLY,
        IDENTITY_CLEAR,
        IDENTITY_EXTERNAL_CHANGE,
        LAUNCHER_RESTORE,
        JOIN_GATE,
        REALMS_GATE,
        JOIN_AUTH,
        AUTHENTICATION_REJECTED,
        RECOVERY,
        RECONNECT,
        DESTINATION_CHANGE,
        VAULT_READ,
        VAULT_TRANSACTION,
        VAULT_ENCRYPT,
        VAULT_COMMIT,
        VAULT_LOCK,
        VAULT_RELINK,
        VAULT_RESET,
        VAULT_WIPE,
        VAULT_NATIVE_CLEANUP,
        VAULT_JOURNAL,
        LEASE_ACQUIRE,
        LEASE_MOVE,
        LEASE_RELEASE,
        INSTANCE_REPORT,
        INSTANCE_RECEIPTS,
        PREFERENCE_SAVE,
        THEME_SETTING,
        UPDATE_SETTING,
        WELCOME_SETTING,
        REVOKE_REQUEST,
        UPDATE_SETUP,
        UPDATE_CHECK,
        UPDATE_RESUME,
        UPDATE_CANCEL,
        UPDATE_MANIFEST_VERIFY,
        UPDATE_JAR_VERIFY,
        UPDATE_STAGE,
        UPDATE_HELPER,
        UPDATE_WAIT,
        UPDATE_APPLY,
        UPDATE_BACKUP,
        UPDATE_ROLLBACK,
        UPDATE_CLEANUP,
        CLEANUP_VERIFY,
        MC_AUTHENTICATION,
        MC_SERVICES,
        MC_RESTRICTIONS,
        MC_PROFILE,
        MC_PROFILE_KEYS,
        MC_SOCIAL,
        MC_REPORTING,
        MC_TELEMETRY,
        MC_CONNECTION,
        MC_SESSION,
        MC_LAUNCHER,
        MC_KEY_FETCH,
        MC_KEY_CLEAR,

        STARTUP_HEADER,
        STORAGE_SNAPSHOT,
        VAULT_UNLOCK,
        KEY_RESOLVE,
        KEY_EXISTING,
        KEY_CREATE,
        KEY_READY,
        LOAD_LIBRARY,
        UI_OPEN,
        UI_STEP,
        UI_ACTION,
        WEBSITE_CLICK,
        WEBSITE_DISPATCH,
        WEBSITE_COPY,
        DOWNLOADS_BROWSER,
        WORKER,
        LINK_CLICK,
        LINK_GUARD,
        LINK_EXISTING,
        LINK_REKEY,
        PAIRING_REQUEST,
        PAIRING_READY,
        PAIRING_POLL,
        PAIRING_EXPIRED,
        PAIRING_DENIED,
        PAIRING_TOKEN,
        GRANT_BIND,
        GRANT_SAVE,
        LINK_COMPLETE,
        BROWSER_CLICK,
        BROWSER_QUEUED,
        BROWSER_DISPATCH,
        BROWSER_COPY,
        BROWSER_CLEAR,
        HTTP_REQUEST,
        HTTP_PREPARE,
        HTTP_PROOF,
        HTTP_SEND,
        HTTP_RESPONSE,
        HTTP_PARSE,
        HTTP_NONCE_RETRY,
        TOKEN_ROTATE_LOCK,
        TOKEN_ROTATE_REQUEST,
        TOKEN_ROTATE_SAVE,
        AUTHORITY_CHECK,
        AUTHORITY_LOST,
        CLEANUP_CHECK,
        CLEANUP_APPLY,
        EVENT_STREAM,
        EVENT_RECEIVED,
        UPDATE_DOWNLOAD,
        PROFILE_CHECK,
        MAINTENANCE,
        RUNTIME_CLOSE
    }

    enum Result {
        STARTED,
        QUEUED,
        SUCCEEDED,
        FAILED,
        SKIPPED,
        EMPTY,
        EXISTING,
        PENDING,
        RETRYING,
        CANCELLED,
        FALLBACK,
        ALLOWED,
        BLOCKED,
        ENABLED,
        DISABLED
    }

    enum Route {
        PAIRING,
        TOKEN,
        AUTHORIZATION,
        ACCOUNTS,
        EXTERNAL,
        KEYS,
        CLEANUP,
        CLEANUP_RECEIPT,
        EVENTS,
        UPDATES,
        SESSIONS,
        MINECRAFT_PROFILE,
        MINECRAFT_PERMISSIONS,
        OTHER
    }

    enum Ui {
        HOME,
        ADD,
        CONNECT,
        IMPORT,
        WORKING,
        READY,
        ERROR,
        UNLOCK,
        PASSWORD,
        RECOVERY,
        SYNC,
        MOVE,
        SETTINGS,
        APPEARANCE,
        UPDATES,
        DEVICE,
        ADVANCED,
        MANAGE,
        DETAILS,
        ACCOUNT_ACTIONS,
        CREDENTIALS,
        STARTING,
        OTHER
    }

    private static final Set<String> CODES =
            new HashSet<>(
                    Arrays.asList(
                            "MINTAUTH_REVOKED",
                            "CLEANUP_UNAVAILABLE",
                            "DEVICE_LIMIT",
                            "DEVICE_UNAVAILABLE",
                            "EVENT_STREAM_UNAVAILABLE",
                            "EXTERNAL_ALREADY_SAVED",
                            "EXTERNAL_CONFLICT",
                            "EXTERNAL_LIMIT",
                            "INPUT_INVALID",
                            "INVALID_DPOP_PROOF",
                            "MINTAUTH_AUTH_REQUIRED",
                            "MINTAUTH_CONFIGURATION",
                            "MINTAUTH_STORAGE_UNAVAILABLE",
                            "NOT_FOUND",
                            "MINTAUTH_RELINK_REQUIRED",
                            "MINTAUTH_DISABLED",
                            "MINTAUTH_ACCESS_EXPIRED",
                            "INVENTORY_FORBIDDEN",
                            "AUTHORIZATION_PENDING",
                            "SLOW_DOWN",
                            "ACCESS_DENIED",
                            "EXPIRED_TOKEN",
                            "INVALID_GRANT",
                            "USE_DPOP_NONCE",
                            "REQUEST_FAILED",
                            "RATE_LIMITED",
                            "MINTAUTH_RATE_LIMITED",
                            "SESSION_REQUEST_COOLDOWN",
                            "MINTAUTH_INVALID_PROOF",
                            "MINTAUTH_REPLAY",
                            "MINTAUTH_INVALID_TOKEN",
                            "MINTAUTH_INVALID_REQUEST",
                            "MINTAUTH_UNAVAILABLE",
                            "MINTAUTH_DEVICE_EXPIRED",
                            "MINTAUTH_PAIRING_UNAVAILABLE",
                            "PAIRING_UNAVAILABLE",
                            "MINTAUTH_PROOF_REQUIRED",
                            "MINTAUTH_NONCE_REQUIRED",
                            "SUPPORT_REQUIRED",
                            "EXTERNAL_TOKEN_REJECTED",
                            "MINECRAFT_UNAVAILABLE",
                            "SESSION_ACCESS_UNAVAILABLE",
                            "SESSION_AUTHORITY_CHANGED",
                            "SESSION_CREDENTIALS_REJECTED",
                            "ACCOUNT_UNAVAILABLE",
                            "USE_MANAGED_ACCOUNT",
                            "EXTERNAL_UNAVAILABLE",
                            "EXTERNAL_HISTORY_CHECK_PENDING"));
    private static final Set<String> LOCAL_CODES =
            new HashSet<>(
                    Arrays.asList(
                            "ACCOUNT_UNAVAILABLE",
                            "CIPHER_LIMIT",
                            "CLEANUP_ALGORITHM",
                            "CLEANUP_BINDING",
                            "CLEANUP_INVALID",
                            "CLEANUP_KEY_UNKNOWN",
                            "CLEANUP_REQUIRED",
                            "CLEANUP_SIGNATURE",
                            "DELIVERY_BINDING",
                            "ENCLAVE_SIGN_FAILED",
                            "ENVELOPE_BINDING",
                            "ENVELOPE_INVALID",
                            "ENVELOPE_LIMIT",
                            "EVENT_DEADLINE",
                            "EVENT_LIMIT",
                            "GCM_AUTHENTICATION",
                            "IDENTITY_BINDING",
                            "IDENTITY_INVALID",
                            "INSTANCE_PATH",
                            "INSTANCE_STILL_ACTIVE",
                            "JSON_INVALID",
                            "JSON_LIMIT",
                            "JSON_OBJECT_REQUIRED",
                            "JSON_TRAILING_CONTENT",
                            "KEY_DELETE_FAILED",
                            "LEASE_INVALID",
                            "LEASE_PATH",
                            "LIMIT",
                            "MISSING_FIELD",
                            "OS_KEYCHAIN_DELETE",
                            "OS_KEY_INVALID",
                            "OS_STORE_UNAVAILABLE",
                            "PAIRING_CODE_FORMAT",
                            "PASSWORD_REQUIRED",
                            "PASSWORD_REQUIREMENTS",
                            "PREPARATION_EXPIRED",
                            "PROFILE_INVALID",
                            "SECRET_SERVICE_LOCKED",
                            "SECRET_SERVICE_UNAVAILABLE",
                            "UNLINK_FIRST",
                            "UPDATE_APPLY_IN_PROGRESS",
                            "UPDATE_ARCHIVE_LIMIT",
                            "UPDATE_ARGUMENTS",
                            "UPDATE_BACKUP",
                            "UPDATE_BUILD",
                            "UPDATE_DIRECTORY",
                            "UPDATE_FILE",
                            "UPDATE_FORMAT",
                            "UPDATE_GAME_VERSION",
                            "UPDATE_HASH",
                            "UPDATE_INSTALL_CHANGED",
                            "UPDATE_INSTALL_PATH",
                            "UPDATE_JAR",
                            "UPDATE_JAVA",
                            "UPDATE_KEY",
                            "UPDATE_LIMIT",
                            "UPDATE_METADATA",
                            "UPDATE_REQUEST",
                            "UPDATE_RESOURCE",
                            "UPDATE_RESPONSE",
                            "UPDATE_SIGNATURE",
                            "UPDATE_SIZE",
                            "UPDATE_SOURCE_BINDING",
                            "UPDATE_STAGE",
                            "UPDATE_SYMLINK",
                            "UPDATE_TARGET",
                            "UPDATE_TARGETS",
                            "UPDATE_TRUNCATED",
                            "UPDATE_UNSIGNED_ENTRY",
                            "UUID_INVALID",
                            "VAULT_LIMIT",
                            "VAULT_LOCKED",
                            "VAULT_LOCKED_OR_CORRUPT",
                            "VAULT_MISSING_OR_CORRUPT",
                            "VAULT_REVOKED",
                            "VAULT_UNINITIALIZED",
                            "NONCE_RETRY_EXHAUSTED",
                            "RESPONSE_DEADLINE",
                            "RESPONSE_LIMIT",
                            "REQUEST_LIMIT",
                            "API_PATH",
                            "PLATFORM_UNSUPPORTED",
                            "PAIRING_WEBSITE_INVALID",
                            "GRANT_BINDING",
                            "ENROLLED_KEY_UNAVAILABLE",
                            "WEBSITE_URL_INVALID",
                            "BROWSER_OPEN_FAILED",
                            "NATIVE_RUNTIME_SOURCE",
                            "NATIVE_RUNTIME_DEPENDENCY",
                            "NATIVE_RUNTIME_VERSION",
                            "NATIVE_RUNTIME_UNAVAILABLE",
                            "OS_KEY_MISSING",
                            "OS_KEYCHAIN_LOCKED",
                            "OS_KEYCHAIN_UNAVAILABLE",
                            "VAULT_SYMLINK",
                            "VAULT_HEADER_LIMIT",
                            "VAULT_PATH",
                            "VAULT_VERSION",
                            "KEY_REFERENCE",
                            "KEY_INVALID",
                            "SIGNATURE_INVALID",
                            "TPM_KEY_UNAVAILABLE",
                            "ENCLAVE_UNAVAILABLE"));
    private static final Set<String> VAULT_CODES =
            new HashSet<>(
                    Arrays.asList(
                            "VAULT_REVOKED",
                            "PASSWORD_REQUIRED",
                            "OS_STORE_UNAVAILABLE",
                            "OS_KEY_MISSING",
                            "VAULT_LOCKED",
                            "VAULT_UNINITIALIZED",
                            "VAULT_LOCKED_OR_CORRUPT",
                            "VAULT_MISSING_OR_CORRUPT"));
    private static final Set<String> CLASSES =
            new HashSet<>(
                    Arrays.asList(
                            "AccountPreparation",
                            "AccountRecords",
                            "ActionButtonStyle",
                            "CleanupVerifier",
                            "ConnectionCleanup",
                            "Crypto",
                            "GameBridge",
                            "InstanceRegistry",
                            "Json",
                            "MemoryProfileKeys",
                            "MintLoadingAnimation",
                            "OfflineAllowance",
                            "OperationFailures",
                            "PlayLease",
                            "ReleaseVerifier",
                            "RuntimePlatform",
                            "SecretStore",
                            "StartupDiagnostics",
                            "TitleTheme",
                            "UpdateInstaller",
                            "UpdateService",
                            "MintAuthRuntime",
                            "ProtocolClient",
                            "NativeStores",
                            "NativeRuntime",
                            "Vault",
                            "HardwareKeys",
                            "PairingWebsiteAction",
                            "AccountWebsiteAction",
                            "FabricGameBridge",
                            "ForgeGameBridge"));
    private static final Set<String> METHODS =
            new HashSet<>(
                    Arrays.asList(
                            "AtomicLong",
                            "FlowDiagnostics",
                            "SecureRandom",
                            "UiOperations",
                            "account",
                            "accountMenuLabel",
                            "accounts",
                            "acquire",
                            "acquireInternal",
                            "activeId",
                            "activeIgn",
                            "allReported",
                            "allReportedInternal",
                            "allowJoin",
                            "allowJoinInternal",
                            "apply",
                            "applyInternal",
                            "atomic",
                            "atomicInternal",
                            "authorization",
                            "automaticUpdates",
                            "b64",
                            "begin",
                            "beginRelink",
                            "beginRelinkInternal",
                            "bind",
                            "busy",
                            "canCreatePasswordVault",
                            "canRestore",
                            "cancel",
                            "cancelPreparation",
                            "checkBeforeAuthentication",
                            "checkBeforeAuthenticationInternal",
                            "checkPreparation",
                            "checkUpdates",
                            "checkWebsiteAtStartup",
                            "cleanup",
                            "cleanupPartial",
                            "clear",
                            "clearActive",
                            "clearInternal",
                            "clearLinkedUse",
                            "clearLocally",
                            "clearLocallyInternal",
                            "clearSecureWebsiteNotice",
                            "clearThisDevice",
                            "close",
                            "closeInternal",
                            "closePrepared",
                            "cloudImportBody",
                            "commitPrepared",
                            "complete",
                            "completedOperation",
                            "configureUpdates",
                            "connectInternal",
                            "consumeWelcome",
                            "copied",
                            "copy",
                            "copySecureWebsiteLink",
                            "cube",
                            "date",
                            "deadline",
                            "decrypt",
                            "decryptEnvelope",
                            "decryptInternal",
                            "defaultRoot",
                            "derSignature",
                            "destructive",
                            "digest",
                            "discardMintInternal",
                            "dismissWelcome",
                            "downloadUpdateInternal",
                            "draw",
                            "ecKey",
                            "emit",
                            "emptyList",
                            "encrypt",
                            "eventLine",
                            "eventsInternal",
                            "failure",
                            "failureMessage",
                            "field",
                            "file",
                            "forPlatform",
                            "hex",
                            "identifier",
                            "importSsid",
                            "installPreparedInternal",
                            "installed",
                            "invalidSession",
                            "isWiped",
                            "javaVendor",
                            "javaVersion",
                            "joseSignature",
                            "leaveWorldInternal",
                            "link",
                            "linked",
                            "local",
                            "locallyRemoved",
                            "logBootstrapFailure",
                            "logRealmsGate",
                            "logUiAction",
                            "logUiFailure",
                            "logUiStep",
                            "main",
                            "matches",
                            "mergeRemote",
                            "message",
                            "moveAccount",
                            "moveRequested",
                            "moveRequestedInternal",
                            "needsPassword",
                            "obj",
                            "object",
                            "offlineAllowed",
                            "offlineAllowedInternal",
                            "olderThanFloor",
                            "onMint",
                            "openDownloadsWebsite",
                            "optional",
                            "owns",
                            "pairingCode",
                            "pairingWebsiteNotice",
                            "pairingWebsiteOpening",
                            "passwordKey",
                            "path",
                            "persistReference",
                            "persisted",
                            "platform",
                            "playingAccountId",
                            "portableGcm",
                            "preparation",
                            "preparationProgress",
                            "prepareAccount",
                            "prepareInternal",
                            "prepareKeyPair",
                            "primary",
                            "privateKey",
                            "profileInternal",
                            "proof",
                            "publicJwk",
                            "publicKey",
                            "random",
                            "randomUUID",
                            "readInternal",
                            "reason",
                            "records",
                            "recoverRekey",
                            "rect",
                            "refresh",
                            "refreshLibrary",
                            "refreshLibraryInternal",
                            "rememberDestination",
                            "removeKey",
                            "removeKeys",
                            "removeLocalCopy",
                            "render",
                            "report",
                            "reportInternal",
                            "reportLocalState",
                            "requestMove",
                            "requestMoveInternal",
                            "resetAfterCleanup",
                            "resetAfterCleanupInternal",
                            "resetClearedVault",
                            "resource",
                            "restoreHidden",
                            "restoreLauncher",
                            "restoreLauncherInternal",
                            "resume",
                            "root",
                            "rsaKey",
                            "rsaKeyInternal",
                            "safe",
                            "safeDirectory",
                            "saveInternal",
                            "savePreference",
                            "secure",
                            "secureDirectory",
                            "secureNewAccountOnWebsite",
                            "secureOnWebsite",
                            "secureWebsiteAttempted",
                            "secureWebsiteNotice",
                            "secureWebsiteOpening",
                            "sha256",
                            "shouldRefreshKeyPair",
                            "silent",
                            "snapshot",
                            "software",
                            "sources",
                            "stage",
                            "stagedRelease",
                            "startHelper",
                            "startHelperInternal",
                            "startupReady",
                            "state",
                            "status",
                            "storageIssue",
                            "store",
                            "string",
                            "submit",
                            "submittedOperation",
                            "syncExisting",
                            "theme",
                            "time",
                            "toggleAutomaticUpdates",
                            "toggleTheme",
                            "tokenHash",
                            "traceStage",
                            "unb64",
                            "unlinkAndClear",
                            "unlockInternal",
                            "unsigned32",
                            "updateInternal",
                            "updateStatus",
                            "uri",
                            "user",
                            "verify",
                            "verifyInternal",
                            "verifyJar",
                            "verifyJarInternal",
                            "website",
                            "beginLink",
                            "initializeKey",
                            "signer",
                            "loadViews",
                            "loadSavedAccounts",
                            "pollPairing",
                            "authorizedCall",
                            "call",
                            "request",
                            "requestInternal",
                            "connection",
                            "read",
                            "open",
                            "openWebsite",
                            "copyPairingWebsiteLink",
                            "unlock",
                            "load",
                            "save",
                            "header",
                            "headerUnlocked",
                            "locked",
                            "update",
                            "write",
                            "remove",
                            "loader",
                            "invoke",
                            "backend",
                            "windowsDataRoot",
                            "api",
                            "check",
                            "create",
                            "createKey",
                            "openKey",
                            "tick",
                            "maintenance",
                            "checkCleanup",
                            "checkCleanupTarget",
                            "startEvents",
                            "events",
                            "downloadUpdate",
                            "profile",
                            "prepareGuidedStorage",
                            "prepare",
                            "select",
                            "install",
                            "installPrepared",
                            "onClient",
                            "openPairingWebsite",
                            "<init>",
                            "<clinit>"));
    private final Consumer<String> info, errors;
    private final String run = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
    private final long started = System.nanoTime();
    private final java.util.EnumMap<Step, Result> states = new java.util.EnumMap<>(Step.class);
    private final LinkedHashMap<Long, AccountPreparation.Phase> attempts = new LinkedHashMap<>();

    synchronized void state(Step step, Result result) {
        if (states.put(step, result) != result) emit(step, result, "");
    }

    synchronized void preparation(long revision, AccountPreparation.Phase phase) {
        if (attempts.put(revision, phase) == phase) return;
        while (attempts.size() > 64) attempts.remove(attempts.keySet().iterator().next());
        Result outcome =
                phase == AccountPreparation.Phase.READY
                        ? Result.SUCCEEDED
                        : phase == AccountPreparation.Phase.FAILED
                                ? Result.FAILED
                                : phase == AccountPreparation.Phase.CANCELLED
                                        ? Result.CANCELLED
                                        : phase == AccountPreparation.Phase.MOVE
                                                ? Result.BLOCKED
                                                : phase == AccountPreparation.Phase.QUEUED
                                                        ? Result.QUEUED
                                                        : Result.STARTED;
        emit(
                Step.PREPARATION_PHASE,
                outcome,
                " attempt=" + Math.max(0, revision) + " phase=" + phase);
    }

    void accountSource(String source) {
        String safe =
                Arrays.asList("MANAGED", "CLOUD", "LOCAL").contains(source) ? source : "OTHER";
        emit(Step.ACCOUNT_SOURCE, Result.SUCCEEDED, " source=" + safe);
    }

    void minecraftJoin(int status, MinecraftJoin.Reason reason) {
        emit(
                Step.MC_AUTHENTICATION,
                reason == null ? Result.SUCCEEDED : Result.FAILED,
                " http_status="
                        + Math.max(0, Math.min(599, status))
                        + " minecraft_reason="
                        + (reason == null ? "ACCEPTED" : reason.name()));
    }

    void multiplayer(MultiplayerAccess access) {
        emit(Step.MC_RESTRICTIONS, Result.SUCCEEDED, " multiplayer=" + access);
    }

    void bridge(GameBridge.Stage stage, GameBridge.Progress progress, Throwable error) {
        Step step;
        switch (stage) {
            case AUTHENTICATION:
                step = Step.MC_AUTHENTICATION;
                break;
            case SERVICES:
                step = Step.MC_SERVICES;
                break;
            case RESTRICTIONS:
                step = Step.MC_RESTRICTIONS;
                break;
            case PROFILE:
                step = Step.MC_PROFILE;
                break;
            case PROFILE_KEYS:
                step = Step.MC_PROFILE_KEYS;
                break;
            case SOCIAL:
                step = Step.MC_SOCIAL;
                break;
            case REPORTING:
                step = Step.MC_REPORTING;
                break;
            case TELEMETRY:
                step = Step.MC_TELEMETRY;
                break;
            case CONNECTION:
                step = Step.MC_CONNECTION;
                break;
            case SESSION:
                step = Step.MC_SESSION;
                break;
            case LAUNCHER:
                step = Step.MC_LAUNCHER;
                break;
            case KEY_FETCH:
                step = Step.MC_KEY_FETCH;
                break;
            case KEY_CLEAR:
                step = Step.MC_KEY_CLEAR;
                break;
            default:
                step = Step.IDENTITY_PREPARE;
        }
        if (error != null) failure(step, error);
        else
            step(
                    step,
                    progress == GameBridge.Progress.FAILED
                            ? Result.FAILED
                            : progress == GameBridge.Progress.STARTED
                                    ? Result.STARTED
                                    : progress == GameBridge.Progress.CANCELLED
                                            ? Result.CANCELLED
                                            : progress == GameBridge.Progress.EMPTY
                                                    ? Result.EMPTY
                                                    : Result.SUCCEEDED);
    }

    private final AtomicLong sequence = new AtomicLong(), requests = new AtomicLong();

    FlowDiagnostics(Consumer<String> info, Consumer<String> errors) {
        this.info = info;
        this.errors = errors;
    }

    static FlowDiagnostics silent() {
        return new FlowDiagnostics(line -> {}, line -> {});
    }

    long requestId() {
        return requests.incrementAndGet();
    }

    private synchronized void emit(Step step, Result result, String safeFields) {
        try {
            String line =
                    "[MintAuth] trace run="
                            + run
                            + " seq="
                            + sequence.incrementAndGet()
                            + " elapsed_ms="
                            + Math.max(0, (System.nanoTime() - started) / 1000000)
                            + " step="
                            + step
                            + " result="
                            + result
                            + safeFields;
            (result == Result.FAILED ? errors : info).accept(line);
        } catch (RuntimeException | LinkageError ignored) {
        }
    }

    void step(Step step, Result result) {
        emit(step, result, "");
    }

    void worker(StartupDiagnostics.Operation op, long task, Result result) {
        emit(Step.WORKER, result, " operation=" + op + " task=" + Math.max(0, task));
    }

    void ui(String name) {
        Ui value;
        try {
            value = Ui.valueOf(name);
        } catch (RuntimeException invalid) {
            value = Ui.OTHER;
        }
        emit(Step.UI_STEP, Result.STARTED, " screen=" + value);
    }

    static Route route(String endpoint) {
        if (endpoint == null) return Route.OTHER;
        String path = endpoint.split("\\?", 2)[0];
        switch (path) {
            case "device/code":
                return Route.PAIRING;
            case "token":
                return Route.TOKEN;
            case "authorization":
            case "revoke":
                return Route.AUTHORIZATION;
            case "external":
                return Route.EXTERNAL;
            case "accounts":
                return Route.ACCOUNTS;
            case "keys":
                return Route.KEYS;
            case "cleanup":
                return Route.CLEANUP;
            case "cleanup/receipt":
                return Route.CLEANUP_RECEIPT;
            case "events":
                return Route.EVENTS;
            default:
                if (path.startsWith("external/")) return Route.EXTERNAL;
                if (path.equals("updates") || path.startsWith("updates/")) return Route.UPDATES;
                if (path.startsWith("sessions/") || path.equals("sessions")) return Route.SESSIONS;
                return Route.OTHER;
        }
    }

    void http(Step step, Result result, long request, Route route, String method, int status) {
        String verb =
                Arrays.asList("GET", "POST", "PUT", "DELETE").contains(method) ? method : "OTHER";
        emit(
                step,
                result,
                " request="
                        + Math.max(0, request)
                        + " route="
                        + route
                        + " method="
                        + verb
                        + (status >= 100 && status <= 599 ? " http_status=" + status : ""));
    }

    private static String hash(String value) throws Exception {
        byte[] digest =
                MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < 8; i++) out.append(String.format(Locale.ROOT, "%02x", digest[i] & 255));
        return out.toString();
    }

    void storage(Path root, JsonObject header) {
        try {
            String generation = header == null ? null : Json.optional(header, "generation");
            String backend = header == null ? "NONE" : Json.optional(header, "backend");
            if (!Arrays.asList(
                            "NONE",
                            "WINDOWS_DPAPI",
                            "MACOS_KEYCHAIN",
                            "LINUX_SECRET_SERVICE",
                            "PASSWORD")
                    .contains(backend)) backend = "OTHER";
            long size = -1;
            try {
                size = Files.size(root.resolve("header.json"));
            } catch (Exception ignored) {
            }
            emit(
                    Step.STORAGE_SNAPSHOT,
                    Result.SUCCEEDED,
                    " location_id="
                            + hash(root.toAbsolutePath().normalize().toString())
                            + " generation_id="
                            + (generation != null && generation.matches("[a-f0-9-]{36}")
                                    ? hash(generation)
                                    : "NONE")
                            + " header_present="
                            + (header != null)
                            + " header_bytes="
                            + size
                            + " device_bound="
                            + (header != null && header.has("deviceId"))
                            + " backend="
                            + backend);
        } catch (Exception | LinkageError ignored) {
        }
    }

    void library(int count, boolean linked) {
        emit(
                Step.LOAD_LIBRARY,
                Result.SUCCEEDED,
                " account_count=" + Math.max(0, count) + " linked=" + linked);
    }

    private static String kind(Throwable error) {
        if (error instanceof java.util.concurrent.CancellationException) return "CANCELLED";
        if (error instanceof NoSuchMethodError) return "NO_SUCH_METHOD";
        if (error instanceof NoClassDefFoundError) return "MISSING_CLASS";
        if (error instanceof UnsatisfiedLinkError) return "NATIVE_LIBRARY";
        if (error instanceof IllegalAccessError) return "CLASS_ACCESS";
        if (error instanceof ExceptionInInitializerError) return "CLASS_INITIALIZATION";
        if (error instanceof NativeFailure) return "NATIVE_STATUS";
        if (error instanceof java.awt.HeadlessException) return "HEADLESS";
        if (error instanceof java.nio.file.AccessDeniedException) return "FILE_ACCESS_DENIED";
        if (error instanceof java.nio.file.NoSuchFileException) return "FILE_MISSING";
        if (error instanceof javax.net.ssl.SSLHandshakeException) return "TLS_HANDSHAKE";
        if (error instanceof javax.net.ssl.SSLException) return "TLS";
        if (error instanceof java.net.UnknownHostException) return "DNS";
        if (error instanceof java.net.SocketTimeoutException) return "TIMEOUT";
        if (error instanceof java.net.ConnectException) return "CONNECT";
        if (error instanceof Vault.Locked) return "VAULT_LOCKED";
        if (error instanceof ProtocolClient.ApiException) return "HTTP";
        if (error instanceof java.security.GeneralSecurityException) return "CRYPTO";
        if (error instanceof com.google.gson.JsonParseException) return "JSON";
        if (error instanceof java.util.concurrent.RejectedExecutionException)
            return "WORKER_UNAVAILABLE";
        String type = error.getClass().getName();
        if (type.equals("com.mojang.authlib.exceptions.InvalidCredentialsException"))
            return "MC_INVALID_SESSION";
        if (type.equals("com.mojang.authlib.exceptions.AuthenticationUnavailableException"))
            return "MC_AUTH_UNAVAILABLE";
        if (type.equals("com.mojang.authlib.exceptions.InsufficientPrivilegesException"))
            return "MC_PRIVACY_RESTRICTED";
        if (type.equals("com.mojang.authlib.exceptions.UserBannedException")) return "MC_BANNED";
        if (type.equals("com.mojang.authlib.exceptions.AuthenticationException"))
            return "MC_AUTH_REJECTED";
        if (error instanceof java.io.IOException) return "IO";
        return "OTHER";
    }

    void failure(Step step, Throwable error) {
        failure(step, error, 0, Route.OTHER);
    }

    void failure(Step step, Throwable error, long request, Route route) {
        try {
            StringBuilder detail = new StringBuilder(" reason=" + OperationFailures.reason(error));
            Result result = Result.FAILED;
            synchronized (this) {
                states.put(step, Result.FAILED);
            }
            if (request > 0)
                detail.append(" request=").append(request).append(" route=").append(route);
            int frames = 0;
            for (int depth = 0; error != null && depth < 8; depth++, error = error.getCause()) {
                if (error instanceof java.util.concurrent.CancellationException)
                    result = Result.CANCELLED;
                detail.append(" cause_").append(depth).append('=').append(kind(error));
                if (LOCAL_CODES.contains(error.getMessage()))
                    detail.append(" client_code=").append(error.getMessage());
                if (error instanceof ProtocolClient.ApiException) {
                    ProtocolClient.ApiException api = (ProtocolClient.ApiException) error;
                    if (api.status >= 100 && api.status <= 599)
                        detail.append(" http_status=").append(api.status);
                    detail.append(" server_code=")
                            .append(CODES.contains(api.code) ? api.code : "OTHER");
                    if (api.code.equals("AUTHORIZATION_PENDING") || api.code.equals("SLOW_DOWN"))
                        result = Result.PENDING;
                }
                if (error instanceof Vault.Locked)
                    detail.append(" storage_code=")
                            .append(
                                    VAULT_CODES.contains(error.getMessage())
                                            ? error.getMessage()
                                            : "OTHER");
                if (error instanceof NativeFailure) {
                    NativeFailure nativeError = (NativeFailure) error;
                    detail.append(" native_api=")
                            .append(nativeError.api)
                            .append(" native_status=")
                            .append(nativeError.status);
                }
                for (StackTraceElement frame : error.getStackTrace()) {
                    if (frames >= 4) break;
                    if (!frame.getClassName().startsWith("online.automint.mintauth.")) continue;
                    String type =
                            frame.getClassName()
                                    .substring(frame.getClassName().lastIndexOf('.') + 1)
                                    .split("\\$", 2)[0];
                    String method = frame.getMethodName();
                    if (method.startsWith("lambda$")) {
                        String[] parts = method.split("\\$");
                        method = parts.length > 1 ? parts[1] : "";
                    }
                    if (!CLASSES.contains(type) || !METHODS.contains(method)) continue;
                    detail.append(" frame_")
                            .append(frames++)
                            .append('=')
                            .append(type)
                            .append('#')
                            .append(method)
                            .append(':')
                            .append(Math.max(0, Math.min(100000, frame.getLineNumber())));
                }
            }
            emit(step, result, detail.toString());
        } catch (RuntimeException | LinkageError ignored) {
        }
    }
}
