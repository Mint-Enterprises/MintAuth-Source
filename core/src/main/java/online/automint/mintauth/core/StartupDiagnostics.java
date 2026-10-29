// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import com.google.gson.JsonObject;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.function.Consumer;

final class StartupDiagnostics {
    enum Storage {
        NOT_INITIALIZED,
        UNLOCKED,
        LOCKED,
        CLEARED,
        UNAVAILABLE
    }

    enum Connection {
        REACHABLE,
        UNCONFIRMED
    }

    enum Authorization {
        VALID,
        NOT_LINKED,
        LOCKED,
        NOT_CHECKED,
        REVOKED,
        RELINK_REQUIRED,
        DISABLED,
        REJECTED,
        CHECK_FAILED
    }

    enum Operation {
        STARTUP,
        STORAGE,
        LINK,
        UNLOCK,
        BROWSER,
        IMPORT,
        SYNC,
        REMOVE,
        RESTORE,
        SELECT,
        REVOKE,
        CLEAR,
        RESET,
        OTHER
    }

    private static String javaVersion() {
        String version = System.getProperty("java.version", "");
        return version.matches(
                        "[0-9]{1,3}(?:\\.[0-9]{1,3}){0,3}(?:_[0-9]{1,5})?(?:[+-][A-Za-z0-9.]{1,12})?")
                ? version
                : "UNAVAILABLE";
    }

    private static String platform() {
        try {
            return RuntimePlatform.identifier(
                    System.getProperty("os.name", ""), System.getProperty("os.arch", ""));
        } catch (RuntimeException error) {
            return "UNSUPPORTED";
        }
    }

    private static String javaVendor() {
        String vendor = System.getProperty("java.vendor", "").toLowerCase(java.util.Locale.ROOT);
        for (String[] known :
                new String[][] {
                    {"azul", "AZUL"},
                    {"adoptium", "ADOPTIUM"},
                    {"oracle", "ORACLE"},
                    {"microsoft", "MICROSOFT"},
                    {"amazon", "AMAZON"},
                    {"apple", "APPLE"},
                    {"openjdk", "OPENJDK"}
                }) if (vendor.contains(known[0])) return known[1];
        return "OTHER";
    }

    void operationFailure(Operation operation, Throwable error) {
        try {
            int http =
                    error instanceof ProtocolClient.ApiException
                            ? ((ProtocolClient.ApiException) error).status
                            : 0;
            emit(
                    "Operation="
                            + operation
                            + " result=FAILED reason="
                            + OperationFailures.reason(error)
                            + " java_version="
                            + javaVersion()
                            + " java_vendor="
                            + javaVendor()
                            + " platform="
                            + platform()
                            + " native_support="
                            + NativeRuntime.state()
                            + (http >= 100 && http <= 599 ? " http_status=" + http : ""));
        } catch (RuntimeException | LinkageError ignored) {
        }
    }

    private final Consumer<String> sink;
    private String lastLocal, lastWebsite;

    StartupDiagnostics(Consumer<String> sink) {
        this.sink = sink;
    }

    private void emit(String line) {
        try {
            sink.accept("[MintAuth] " + line);
        } catch (RuntimeException | LinkageError ignored) {
        }
    }

    private static String field(JsonObject value, String name, String pattern) {
        try {
            String result = Json.optional(value, name);
            return result != null && result.matches(pattern) ? result : "UNAVAILABLE";
        } catch (RuntimeException | LinkageError ignored) {
            return "UNAVAILABLE";
        }
    }

    private static String user(JsonObject auth) {
        return auth == null ? "UNAVAILABLE" : field(auth, "subject", "[A-Za-z0-9_-]{1,128}");
    }

    private static String date(JsonObject value, String name) {
        try {
            return Instant.parse(Json.string(value, name)).toString();
        } catch (RuntimeException | LinkageError ignored) {
            return "UNAVAILABLE";
        }
    }

    void artifact(String target, Path jar) {
        emit(
                "Runtime java_version="
                        + javaVersion()
                        + " java_vendor="
                        + javaVendor()
                        + " platform="
                        + platform()
                        + " native_support="
                        + NativeRuntime.state());
        String safeTarget =
                target != null && target.matches("forge-1\\.8\\.9|fabric-1\\.21\\.11|fabric-26\\.3")
                        ? target
                        : "UNKNOWN";
        String commit = null;
        try {
            JsonObject build =
                    Json.object(
                            new String(
                                    ReleaseVerifier.resource("build.json"), StandardCharsets.UTF_8),
                            4096);
            commit = field(build, "commit", "[a-f0-9]{40}");
            emit(
                    "Build version="
                            + field(build, "version", "[A-Za-z0-9.+_-]{1,64}")
                            + " target="
                            + safeTarget
                            + " commit="
                            + commit);
        } catch (Exception | LinkageError ignored) {
            emit("Build version=UNAVAILABLE target=" + safeTarget + " commit=UNAVAILABLE");
        }
        try {
            X509Certificate cert =
                    (X509Certificate)
                            CertificateFactory.getInstance("X.509")
                                    .generateCertificate(
                                            new ByteArrayInputStream(
                                                    ReleaseVerifier.resource("jar-signing.crt")));
            long now = System.currentTimeMillis();
            emit(
                    "Signer certificate_sha256="
                            + ReleaseVerifier.hex(Crypto.sha256(cert.getEncoded()))
                            + " certificate_dates="
                            + (now < cert.getNotBefore().getTime()
                                    ? "NOT_YET_VALID"
                                    : now > cert.getNotAfter().getTime() ? "EXPIRED" : "VALID")
                            + " valid_from="
                            + cert.getNotBefore().toInstant()
                            + " valid_until="
                            + cert.getNotAfter().toInstant());
        } catch (Exception | LinkageError ignored) {
            emit("Signer certificate_dates=UNAVAILABLE");
        }
        try {
            jar(jar, safeTarget, commit, new ReleaseVerifier());
        } catch (Exception | LinkageError ignored) {
            emit("JAR signature=UNVERIFIED_OR_UNAVAILABLE");
        }
    }

    void jar(Path jar, String target, String commit, ReleaseVerifier verifier) {
        try {
            if (commit == null || !commit.matches("[a-f0-9]{40}"))
                throw new IllegalStateException();
            verifier.verifyJar(jar, target, null, commit);
            emit("JAR signature=VERIFIED_PINNED_CERTIFICATE sha256=" + ReleaseVerifier.digest(jar));
        } catch (Exception | LinkageError ignored) {
            emit("JAR signature=UNVERIFIED_OR_UNAVAILABLE");
        }
    }

    synchronized void local(Storage storage, JsonObject auth, boolean softwareKey) {
        String line =
                "Local storage="
                        + storage
                        + " linked="
                        + (storage == Storage.LOCKED || storage == Storage.UNAVAILABLE
                                ? "UNKNOWN"
                                : Boolean.toString(auth != null))
                        + " cached_user_id="
                        + user(auth)
                        + " grant_expires_at="
                        + (auth == null ? "NONE" : date(auth, "authorization_expires_at"))
                        + " device_key="
                        + (storage != Storage.UNLOCKED
                                ? "UNAVAILABLE"
                                : softwareKey
                                        ? "OS_OR_PASSWORD_PROTECTED_SOFTWARE"
                                        : "NATIVE_SIGNER")
                        + " cached_authorization=NOT_CHECKED";
        if (!line.equals(lastLocal)) {
            lastLocal = line;
            emit(line);
        }
    }

    synchronized void website(
            Connection connection,
            Authorization authorization,
            JsonObject auth,
            Integer httpStatus) {
        String line =
                "Website origin="
                        + ProtocolClient.ORIGIN
                        + " connection="
                        + connection
                        + " authorization="
                        + authorization
                        + " user_id="
                        + (authorization == Authorization.VALID ? user(auth) : "UNCONFIRMED")
                        + (httpStatus == null ? "" : " http_status=" + httpStatus);
        if (!line.equals(lastWebsite)) {
            lastWebsite = line;
            emit(line + " checked_at=" + Instant.now());
        }
    }

    void websiteFailure(Exception error) {
        if (!(error instanceof ProtocolClient.ApiException)) {
            website(Connection.UNCONFIRMED, Authorization.CHECK_FAILED, null, null);
            return;
        }
        ProtocolClient.ApiException api = (ProtocolClient.ApiException) error;
        Authorization state;
        switch (api.code) {
            case "MINTAUTH_REVOKED":
                state = Authorization.REVOKED;
                break;
            case "MINTAUTH_RELINK_REQUIRED":
                state = Authorization.RELINK_REQUIRED;
                break;
            case "MINTAUTH_DISABLED":
                state = Authorization.DISABLED;
                break;
            default:
                state =
                        api.status == 401 || api.status == 403
                                ? Authorization.REJECTED
                                : Authorization.CHECK_FAILED;
        }
        website(Connection.REACHABLE, state, null, api.status);
    }
}
