// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import static org.junit.Assert.*;

import com.google.gson.JsonObject;

import org.junit.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class StartupDiagnosticsTest {
    @Test
    public void allowlistsFieldsAndSuppressesUnchangedHeartbeats() {
        List<String> lines = new ArrayList<>();
        StartupDiagnostics log = new StartupDiagnostics(lines::add);
        JsonObject auth = Json.obj("subject", "test_user_123");
        auth.addProperty("authorization_expires_at", "2026-11-01T00:00:00Z");
        auth.addProperty("access_token", "SECRET_ACCESS_SENTINEL");
        auth.addProperty("refresh_token", "SECRET_REFRESH_SENTINEL");
        auth.addProperty("ssid", "SECRET_SSID_SENTINEL");
        auth.addProperty("device_code", "SECRET_PAIRING_SENTINEL");
        log.local(StartupDiagnostics.Storage.UNLOCKED, auth, true);
        log.website(
                StartupDiagnostics.Connection.REACHABLE,
                StartupDiagnostics.Authorization.VALID,
                auth,
                null);
        log.website(
                StartupDiagnostics.Connection.REACHABLE,
                StartupDiagnostics.Authorization.VALID,
                auth,
                null);
        assertEquals(2, lines.size());
        String output = String.join("\n", lines);
        assertTrue(output.contains("user_id=test_user_123"));
        assertTrue(output.contains("grant_expires_at=2026-11-01T00:00:00Z"));
        assertFalse(output.contains("SECRET_"));
        log.websiteFailure(new IOException("SECRET_RESPONSE_SENTINEL"));
        assertTrue(lines.get(2).contains("connection=UNCONFIRMED authorization=CHECK_FAILED"));
        assertFalse(lines.get(2).contains("test_user_123"));
        log.websiteFailure(new ProtocolClient.ApiException("MINTAUTH_REVOKED", 401));
        assertTrue(lines.get(3).contains("connection=REACHABLE authorization=REVOKED"));
        assertFalse(String.join("\n", lines).contains("SECRET_"));
    }

    @Test
    public void rejectsLogInjectionAndMalformedFields() {
        List<String> lines = new ArrayList<>();
        StartupDiagnostics log = new StartupDiagnostics(lines::add);
        JsonObject auth = Json.obj("subject", "user\nFORGED_LOG");
        auth.addProperty("authorization_expires_at", "SECRET_DATE");
        log.local(StartupDiagnostics.Storage.UNLOCKED, auth, true);
        log.website(
                StartupDiagnostics.Connection.REACHABLE,
                StartupDiagnostics.Authorization.VALID,
                auth,
                null);
        assertFalse(String.join("", lines).contains("FORGED_LOG"));
        assertFalse(String.join("", lines).contains("SECRET_DATE"));
        assertTrue(lines.get(0).contains("cached_user_id=UNAVAILABLE"));
        log.local(StartupDiagnostics.Storage.LOCKED, null, false);
        assertTrue(lines.get(2).contains("device_key=UNAVAILABLE"));
    }

    @Test
    public void loggerFailureCannotBreakAuthorization() {
        StartupDiagnostics log =
                new StartupDiagnostics(
                        line -> {
                            throw new IllegalStateException();
                        });
        log.local(StartupDiagnostics.Storage.LOCKED, null, false);
        log.websiteFailure(new IOException("secret"));
    }
}
