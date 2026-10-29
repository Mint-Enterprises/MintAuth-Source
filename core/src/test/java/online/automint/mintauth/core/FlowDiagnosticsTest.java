// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import static org.junit.Assert.*;

import com.google.gson.JsonObject;

import org.junit.Test;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.KeyPair;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

public class FlowDiagnosticsTest {
    private static final String SECRET = "SECRET_SENTINEL_NEVER_LOG_ME";

    private static HttpURLConnection response(String url, int status, String json, String nonce)
            throws IOException {
        return new HttpURLConnection(new URL(url)) {
            public void connect() {}

            public void disconnect() {}

            public boolean usingProxy() {
                return false;
            }

            public int getResponseCode() {
                return status;
            }

            public OutputStream getOutputStream() {
                return new ByteArrayOutputStream();
            }

            public InputStream getInputStream() {
                return new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8));
            }

            public InputStream getErrorStream() {
                return getInputStream();
            }

            public String getHeaderField(String name) {
                return name.equals("DPoP-Nonce") ? nonce : null;
            }
        };
    }

    private static void absentSecrets(List<String> lines, String... additional) {
        String text = String.join("\n", lines);
        assertFalse(text, text.contains(SECRET));
        for (String secret : additional) assertFalse(text, text.contains(secret));
    }

    @Test
    public void errorsRetainUsefulNativeAndSourceDetailsButNoMessagesOrPaths() {
        List<String> lines = new ArrayList<>();
        FlowDiagnostics trace = new FlowDiagnostics(lines::add, lines::add);
        NativeFailure nativeError = new NativeFailure(NativeFailure.Api.SHELL_EXECUTE, 31);
        nativeError.setStackTrace(
                new StackTraceElement[] {
                    new StackTraceElement(
                            "online.automint.mintauth.core.NativeStores",
                            "openWebsite",
                            SECRET,
                            72),
                    new StackTraceElement(
                            "online.automint.mintauth.core." + SECRET, SECRET, SECRET, 1)
                });
        Vault.Locked failure = new Vault.Locked(SECRET);
        failure.initCause(nativeError);
        trace.failure(FlowDiagnostics.Step.BROWSER_DISPATCH, failure);
        trace.failure(
                FlowDiagnostics.Step.HTTP_REQUEST, new ProtocolClient.ApiException(SECRET, 403));
        String text = String.join("\n", lines);
        assertTrue(text.contains("native_api=SHELL_EXECUTE native_status=31"));
        assertTrue(text.contains("frame_0=NativeStores#openWebsite:72"));
        assertTrue(text.contains("server_code=OTHER"));
        assertTrue(text.contains("http_status=403"));
        absentSecrets(lines);
    }

    @Test
    public void nonceRetryLogsEveryHttpPhaseWithoutLeakingAnyHttpMaterial() throws Exception {
        List<String> lines = new ArrayList<>();
        AtomicInteger calls = new AtomicInteger();
        ProtocolClient client =
                new ProtocolClient(
                        (url, method) ->
                                calls.incrementAndGet() == 1
                                        ? response(
                                                url,
                                                401,
                                                "{\"code\":\"USE_DPOP_NONCE\",\"private\":\""
                                                        + SECRET
                                                        + "\"}",
                                                SECRET)
                                        : response(
                                                url,
                                                200,
                                                "{\"private\":\"" + SECRET + "\"}",
                                                null));
        client.setDiagnostics(new FlowDiagnostics(lines::add, lines::add));
        KeyPair key = Crypto.ecKey();
        Crypto.Signer signer = Crypto.software(key.getPrivate(), Crypto.publicJwk(key.getPublic()));
        assertEquals(
                SECRET,
                Json.string(
                        client.request(
                                "POST", "device/code", Json.obj("secret", SECRET), SECRET, signer),
                        "private"));
        String text = String.join("\n", lines);
        for (String step :
                new String[] {
                    "HTTP_REQUEST",
                    "HTTP_PREPARE",
                    "HTTP_PROOF",
                    "HTTP_SEND",
                    "HTTP_RESPONSE",
                    "HTTP_PARSE",
                    "HTTP_NONCE_RETRY"
                }) assertTrue(step, text.contains("step=" + step));
        assertTrue(text.contains("route=PAIRING"));
        assertTrue(text.contains("result=RETRYING"));
        assertTrue(text.contains("http_status=200"));
        assertEquals(2, calls.get());
        absentSecrets(
                lines,
                Json.string(signer.publicJwk(), "x"),
                Crypto.b64(key.getPrivate().getEncoded()));
    }

    @Test
    public void connectionAndParseFailuresAreLoggedWithoutRawExceptionOrBody() throws Exception {
        List<String> lines = new ArrayList<>();
        FlowDiagnostics trace = new FlowDiagnostics(lines::add, lines::add);
        ProtocolClient dns =
                new ProtocolClient(
                        (url, method) -> {
                            throw new UnknownHostException(SECRET);
                        });
        dns.setDiagnostics(trace);
        try {
            dns.request(
                    "GET",
                    "cleanup?locator=" + String.join("", Collections.nCopies(43, "a")),
                    null,
                    null,
                    null);
            fail();
        } catch (UnknownHostException expected) {
        }
        ProtocolClient malformed =
                new ProtocolClient(
                        (url, method) ->
                                response(url, 200, "{\"private\":\"" + SECRET + "\",", null));
        malformed.setDiagnostics(trace);
        try {
            malformed.request("GET", "keys", null, null, null);
            fail();
        } catch (Exception expected) {
        }
        String text = String.join("\n", lines);
        assertTrue(text.contains("cause_0=DNS"));
        assertTrue(text.contains("cause_0=JSON"));
        assertTrue(text.contains("route=CLEANUP"));
        assertFalse(text.contains("locator="));
        absentSecrets(lines);
    }

    @Test
    public void approvalPendingIsInformationalAndBrowserFailureHasCompleteStepTrace() {
        List<String> info = new ArrayList<>(), errors = new ArrayList<>();
        FlowDiagnostics trace = new FlowDiagnostics(info::add, errors::add);
        trace.failure(
                FlowDiagnostics.Step.PAIRING_POLL,
                new ProtocolClient.ApiException("AUTHORIZATION_PENDING", 400));
        assertTrue(errors.isEmpty());
        assertTrue(info.get(0).contains("result=PENDING"));
        PairingWebsiteAction action =
                new PairingWebsiteAction(
                        Runnable::run,
                        uri -> {
                            throw new NativeFailure(NativeFailure.Api.SHELL_EXECUTE, 31);
                        },
                        error -> {},
                        trace);
        action.begin("ABCD-EFGH");
        action.open();
        action.copied(true);
        assertTrue(
                errors.stream()
                        .anyMatch(
                                line ->
                                        line.contains("step=BROWSER_DISPATCH result=FAILED")
                                                && line.contains("native_status=31")));
        String text = String.join("\n", info);
        assertTrue(text.contains("step=BROWSER_CLICK"));
        assertTrue(text.contains("step=BROWSER_QUEUED"));
        assertTrue(text.contains("step=BROWSER_COPY"));
        absentSecrets(info, "ABCDEFGH", "ABCD-EFGH", "#code=");
        absentSecrets(errors, "ABCDEFGH", "ABCD-EFGH", "#code=");
    }

    @Test
    public void storageDiagnosticsIdentifyDifferentViewsWithoutRevealingPathsOrGeneration()
            throws Exception {
        List<String> lines = new ArrayList<>();
        FlowDiagnostics trace = new FlowDiagnostics(lines::add, lines::add);
        Path root = Files.createTempDirectory(SECRET);
        String generation = UUID.randomUUID().toString();
        JsonObject h = Json.obj("generation", generation);
        h.addProperty("backend", "WINDOWS_DPAPI");
        h.addProperty("deviceId", SECRET);
        h.addProperty("cleanupLocator", SECRET);
        trace.storage(root, h);
        trace.ui(SECRET);
        assertTrue(lines.get(0).contains("location_id="));
        assertTrue(lines.get(0).contains("generation_id="));
        assertTrue(lines.get(0).contains("device_bound=true"));
        assertTrue(lines.get(1).contains("screen=OTHER"));
        absentSecrets(lines, root.toString(), generation);
    }

    @Test
    public void completeSyntheticLinkTraceCoversApprovalAndPersistenceWithoutCredentialLeaks()
            throws Exception {
        List<String> lines = Collections.synchronizedList(new ArrayList<>());
        final PreparationLifecycleTest.Fixture[] holder = new PreparationLifecycleTest.Fixture[1];
        AtomicInteger polls = new AtomicInteger();
        PreparationLifecycleTest.Bridge bridge =
                new PreparationLifecycleTest.Bridge() {
                    @Override
                    public void logDiagnostic(String line) {
                        lines.add(line);
                    }

                    @Override
                    public void logFailureDiagnostic(String line) {
                        lines.add(line);
                    }
                };
        ProtocolClient client =
                new ProtocolClient(
                        (url, method) -> {
                            if (url.endsWith("/device/code"))
                                return response(
                                        url,
                                        200,
                                        "{\"user_code\":\"ABCD-EFGH\",\"device_code\":\""
                                                + SECRET
                                                + "\",\"verification_uri_complete\":\"https://automint.online/mintauth/link#code=ABCDEFGH\"}",
                                        null);
                            if (url.endsWith("/token")) {
                                if (polls.incrementAndGet() == 1)
                                    return response(
                                            url, 400, "{\"code\":\"AUTHORIZATION_PENDING\"}", null);
                                try {
                                    JsonObject token =
                                            Json.obj("device_id", UUID.randomUUID().toString());
                                    token.addProperty(
                                            "vault_generation",
                                            Json.string(holder[0].vault.header(), "generation"));
                                    token.addProperty("access_token", SECRET);
                                    token.addProperty("refresh_token", SECRET);
                                    return response(url, 200, Json.GSON.toJson(token), null);
                                } catch (Exception error) {
                                    throw new IOException(error);
                                }
                            }
                            if (url.endsWith("/accounts") || url.endsWith("/external"))
                                return response(url, 200, "{\"accounts\":[]}", null);
                            throw new AssertionError("Unexpected synthetic endpoint");
                        });
        try (PreparationLifecycleTest.Fixture fixture =
                new PreparationLifecycleTest.Fixture(bridge, client, false)) {
            holder[0] = fixture;
            KeyPair pair = Crypto.ecKey();
            JsonObject key = Json.obj("reference", "SOFTWARE");
            key.addProperty("privateKey", Crypto.b64(pair.getPrivate().getEncoded()));
            key.add("publicKey", Crypto.publicJwk(pair.getPublic()));
            fixture.vault.update(
                    data -> {
                        data.add("deviceKey", key);
                        return null;
                    });
            fixture.runtime.loadSavedAccounts();
            fixture.runtime.logUiStep("CONNECT");
            fixture.runtime.beginLink();
            long task = fixture.runtime.submittedOperation();
            PreparationLifecycleTest.await(() -> fixture.runtime.completedOperation(task) != null);
            assertTrue(fixture.runtime.completedOperation(task).succeeded);
            java.lang.reflect.Method poll = MintAuthRuntime.class.getDeclaredMethod("pollPairing");
            poll.setAccessible(true);
            poll.invoke(fixture.runtime);
            assertFalse(fixture.runtime.linked());
            poll.invoke(fixture.runtime);
            assertTrue(fixture.runtime.linked());
            assertTrue(fixture.vault.read().has("authorization"));
            String text = String.join("\n", lines);
            for (String step :
                    new String[] {
                        "UI_STEP",
                        "LINK_CLICK",
                        "KEY_READY",
                        "PAIRING_REQUEST",
                        "PAIRING_READY",
                        "PAIRING_POLL",
                        "PAIRING_TOKEN",
                        "GRANT_BIND",
                        "GRANT_SAVE",
                        "LINK_COMPLETE",
                        "LOAD_LIBRARY"
                    }) assertTrue(step, text.contains("step=" + step));
            absentSecrets(
                    lines, "ABCDEFGH", "ABCD-EFGH", Crypto.b64(pair.getPrivate().getEncoded()));
        }
    }

    @Test
    public void rejectedBrowserWorkIsLoggedAndDoesNotStayOpeningForever() {
        List<String> lines = new ArrayList<>();
        FlowDiagnostics trace = new FlowDiagnostics(lines::add, lines::add);
        java.util.concurrent.Executor rejected =
                job -> {
                    throw new java.util.concurrent.RejectedExecutionException(SECRET);
                };
        PairingWebsiteAction action =
                new PairingWebsiteAction(
                        rejected,
                        uri -> {
                            fail();
                        },
                        error -> {},
                        trace);
        action.begin("ABCD-EFGH");
        action.open();
        assertFalse(action.opening());
        assertTrue(action.notice().contains("Copy link"));
        assertTrue(
                lines.stream()
                        .anyMatch(
                                line ->
                                        line.contains("step=BROWSER_QUEUED result=FAILED")
                                                && line.contains("cause_0=WORKER_UNAVAILABLE")));
        absentSecrets(lines);
    }

    @Test
    public void brokenLoggingCannotBreakHttpOrBrowserOutcomes() throws Exception {
        FlowDiagnostics broken =
                new FlowDiagnostics(
                        line -> {
                            throw new IllegalStateException(SECRET);
                        },
                        line -> {
                            throw new IllegalStateException(SECRET);
                        });
        ProtocolClient client = new ProtocolClient((url, method) -> response(url, 200, "{}", null));
        client.setDiagnostics(broken);
        assertNotNull(client.request("GET", "keys", null, null, null));
        PairingWebsiteAction action =
                new PairingWebsiteAction(
                        Runnable::run,
                        uri -> {
                            throw new IOException(SECRET);
                        },
                        error -> {},
                        broken);
        action.begin("ABCD-EFGH");
        action.open();
        assertFalse(action.opening());
        assertTrue(action.notice().contains("Copy link"));
    }
}
