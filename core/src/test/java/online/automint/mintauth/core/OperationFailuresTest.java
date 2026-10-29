// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import static org.junit.Assert.*;

import org.junit.Test;

import java.io.IOException;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.util.*;

import javax.net.ssl.SSLHandshakeException;

public class OperationFailuresTest {
    @Test
    public void nativeAndKeyFailuresAreNotReportedAsConnectionProblems() throws Exception {
        Vault.Locked nativeFailure = new Vault.Locked("OS_STORE_UNAVAILABLE");
        nativeFailure.initCause(new NoSuchMethodError("synthetic secret native detail"));
        assertEquals(
                OperationFailures.Reason.NATIVE_RUNTIME, OperationFailures.reason(nativeFailure));
        assertTrue(OperationFailures.message(nativeFailure).contains("[NATIVE]"));
        assertFalse(OperationFailures.message(nativeFailure).contains("secret"));
        assertEquals(
                OperationFailures.Reason.SIGNING_KEY,
                OperationFailures.reason(new GeneralSecurityException("secret key reference")));
        assertTrue(
                OperationFailures.message(new SSLHandshakeException("secret certificate detail"))
                        .contains("[TLS]"));
        assertTrue(
                OperationFailures.message(new UnknownHostException("secret address"))
                        .contains("[DNS]"));
        assertTrue(
                OperationFailures.message(
                                new ProtocolClient.ApiException("synthetic_secret_code", 401))
                        .contains("[REJECTED]"));
        assertFalse(
                OperationFailures.message(new IOException("secret unclassified response"))
                        .contains("connection"));
    }

    @Test
    public void nativeSourceFailureIsClassifiedThroughTheVaultWrapper() {
        Vault.Locked failure = new Vault.Locked("OS_STORE_UNAVAILABLE");
        failure.initCause(new IOException("NATIVE_RUNTIME_SOURCE"));
        assertEquals(OperationFailures.Reason.NATIVE_RUNTIME, OperationFailures.reason(failure));
        assertTrue(OperationFailures.message(failure).contains("[NATIVE]"));
    }

    @Test
    public void failureDiagnosticsAreAllowlistedAndNeverDumpCausesOrBodies() {
        List<String> lines = new ArrayList<>();
        StartupDiagnostics log = new StartupDiagnostics(lines::add);
        log.operationFailure(
                StartupDiagnostics.Operation.LINK,
                new SSLHandshakeException("SECRET_TOKEN_SENTINEL"));
        log.operationFailure(
                StartupDiagnostics.Operation.STORAGE,
                new NoSuchMethodError("SECRET_PATH_SENTINEL"));
        log.operationFailure(
                StartupDiagnostics.Operation.LINK,
                new ProtocolClient.ApiException("SECRET_RESPONSE_SENTINEL", 403));
        String output = String.join("\n", lines);
        assertFalse(output.contains("SECRET_"));
        assertTrue(output.contains("reason=TLS"));
        assertTrue(output.contains("reason=NATIVE_RUNTIME"));
        assertTrue(output.contains("http_status=403"));
        assertTrue(output.contains("java_version="));
        assertTrue(output.contains("platform="));
        assertTrue(output.contains("native_support="));
    }

    @Test
    public void brokenLoggerCannotChangeTheFailurePath() {
        StartupDiagnostics log =
                new StartupDiagnostics(
                        line -> {
                            throw new IllegalStateException("synthetic logger failure");
                        });
        log.operationFailure(
                StartupDiagnostics.Operation.LINK, new SSLHandshakeException("secret"));
    }
}
