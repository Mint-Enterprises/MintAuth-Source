// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import static org.junit.Assert.*;

import org.junit.Test;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

public class MinecraftJoinTest {
    private static final String UUID = "0123456789abcdef0123456789abcdef";
    private static final String TOKEN = "SYNTHETIC_SSID_NEVER_LOG";
    private static final String DIGEST = "-1234abcdef";

    static class Response extends HttpURLConnection {
        final int status;
        final String body;
        final ByteArrayOutputStream sent = new ByteArrayOutputStream();
        boolean disconnected;

        Response(String url, int status, String body) throws Exception {
            super(new URL(url));
            this.status = status;
            this.body = body;
        }

        public void connect() {}

        public void disconnect() {
            disconnected = true;
        }

        public boolean usingProxy() {
            return false;
        }

        public int getResponseCode() {
            return status;
        }

        public OutputStream getOutputStream() {
            return sent;
        }

        public InputStream getErrorStream() {
            return new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8));
        }
    }

    private MinecraftJoin transport(
            int status, String body, List<String> lines, AtomicReference<Response> captured) {
        MinecraftJoin transport =
                new MinecraftJoin(
                        (url, method) -> {
                            assertEquals(
                                    "https://sessionserver.mojang.com/session/minecraft/join", url);
                            assertEquals("POST", method);
                            try {
                                Response response = new Response(url, status, body);
                                captured.set(response);
                                return response;
                            } catch (Exception failure) {
                                throw new IOException(failure);
                            }
                        });
        transport.setDiagnostics(new FlowDiagnostics(lines::add, lines::add));
        return transport;
    }

    @Test
    public void successUsesOriginalProtocolWithoutLeakingIdentity() throws Exception {
        List<String> lines = new ArrayList<>();
        AtomicReference<Response> captured = new AtomicReference<>();
        transport(204, "", lines, captured).join(UUID, TOKEN, DIGEST);
        Response response = captured.get();
        com.google.gson.JsonObject payload =
                Json.object(new String(response.sent.toByteArray(), StandardCharsets.UTF_8), 4096);
        assertEquals(3, payload.size());
        assertEquals(TOKEN, Json.string(payload, "accessToken"));
        assertEquals(UUID, Json.string(payload, "selectedProfile"));
        assertEquals(DIGEST, Json.string(payload, "serverId"));
        assertFalse(response.getInstanceFollowRedirects());
        assertTrue(response.disconnected);
        assertEquals("application/json", response.getRequestProperty("Content-Type"));
        String log = String.join("\n", lines);
        assertTrue(log.contains("http_status=204 minecraft_reason=ACCEPTED"));
        assertFalse(log.contains(TOKEN));
        assertFalse(log.contains(UUID));
        assertFalse(log.contains(DIGEST));
    }

    @Test
    public void modernPrivilegeErrorWithoutLegacyMessageIsNotInvalidSession() throws Exception {
        List<String> lines = new ArrayList<>();
        AtomicReference<Response> captured = new AtomicReference<>();
        try {
            transport(
                            403,
                            "{\"error\":\"InsufficientPrivilegesException\",\"errorMessage\":\""
                                    + TOKEN
                                    + "\"}",
                            lines,
                            captured)
                    .join(UUID, TOKEN, DIGEST);
            fail();
        } catch (MinecraftJoin.Failure failure) {
            assertEquals(MinecraftJoin.Reason.PRIVILEGES, failure.reason);
            assertEquals(403, failure.status);
            assertTrue(failure.getMessage().contains("[MC_PRIVILEGES]"));
            assertFalse(failure.getMessage().contains(TOKEN));
        }
        String log = String.join("\n", lines);
        assertTrue(log.contains("http_status=403 minecraft_reason=PRIVILEGES"));
        assertFalse(log.contains(TOKEN));
        assertTrue(captured.get().disconnected);
        try {
            transport(403, "{\"error\":\"InsufficientPrivilegesException\"}", lines, captured)
                    .join(UUID, TOKEN, DIGEST);
            fail();
        } catch (MinecraftJoin.Failure failure) {
            assertEquals(MinecraftJoin.Reason.PRIVILEGES, failure.reason);
        }
    }

    @Test
    public void statusAndKnownErrorsNeverTreatRestrictionsOrUnknownRejectionsAsExpiry()
            throws Exception {
        assertEquals(MinecraftJoin.Reason.BANNED, MinecraftJoin.reason(403, "UserBannedException"));
        assertEquals(
                MinecraftJoin.Reason.INVALID_SESSION,
                MinecraftJoin.reason(403, "InvalidCredentialsException"));
        assertEquals(
                MinecraftJoin.Reason.INVALID_SESSION,
                MinecraftJoin.reason(403, "InvalidTokenException"));
        assertEquals(
                MinecraftJoin.Reason.INVALID_SESSION,
                MinecraftJoin.reason(403, "ForbiddenOperationException"));
        assertEquals(MinecraftJoin.Reason.INVALID_SESSION, MinecraftJoin.reason(401, null));
        assertEquals(
                MinecraftJoin.Reason.UNAVAILABLE,
                MinecraftJoin.reason(403, "AuthenticationUnavailableException"));
        assertEquals(
                MinecraftJoin.Reason.UNAVAILABLE,
                MinecraftJoin.reason(503, "InvalidTokenException"));
        assertEquals(
                MinecraftJoin.Reason.RATE_LIMITED,
                MinecraftJoin.reason(429, "InvalidTokenException"));
        for (int status : new int[] {200, 201, 301, 302, 307, 400, 403}) {
            try {
                transport(
                                status,
                                "{\"error\":\"unknown\"}",
                                new ArrayList<>(),
                                new AtomicReference<>())
                        .join(UUID, TOKEN, DIGEST);
                fail();
            } catch (MinecraftJoin.Failure failure) {
                assertEquals(MinecraftJoin.Reason.REJECTED, failure.reason);
            }
        }
    }

    @Test
    public void malformedOrOversizedErrorsStayBoundedAndNeverEchoResponseText() throws Exception {
        for (String body :
                new String[] {
                    "not json " + TOKEN,
                    "{\"error\":{\"secret\":\"" + TOKEN + "\"}}",
                    "{\"error\":\"InvalidTokenException\"} trailing",
                    String.join("", Collections.nCopies(9000, "x"))
                }) {
            List<String> lines = new ArrayList<>();
            AtomicReference<Response> captured = new AtomicReference<>();
            try {
                transport(403, body, lines, captured).join(UUID, TOKEN, DIGEST);
                fail();
            } catch (IOException failure) {
                if (failure instanceof MinecraftJoin.Failure)
                    assertEquals(
                            MinecraftJoin.Reason.REJECTED,
                            ((MinecraftJoin.Failure) failure).reason);
                assertFalse(String.valueOf(failure.getMessage()).contains(TOKEN));
            }
            assertFalse(String.join("\n", lines).contains(TOKEN));
            assertTrue(captured.get().disconnected);
        }
    }

    @Test
    public void badInputsDoNotSendAnythingAndNetworkExceptionsAreRedacted() throws Exception {
        AtomicReference<Response> captured = new AtomicReference<>();
        List<String> lines = new ArrayList<>();
        MinecraftJoin transport = transport(204, "", lines, captured);
        for (String[] args :
                new String[][] {
                    {null, TOKEN, DIGEST},
                    {"bad", TOKEN, DIGEST},
                    {UUID, null, DIGEST},
                    {UUID, "short", DIGEST},
                    {UUID, TOKEN, "bad/url"}
                }) {
            try {
                transport.join(args[0], args[1], args[2]);
                fail();
            } catch (MinecraftJoin.Failure failure) {
                assertEquals(MinecraftJoin.Reason.REJECTED, failure.reason);
            }
        }
        assertNull(captured.get());
        MinecraftJoin failed =
                new MinecraftJoin(
                        (url, method) -> {
                            throw new IOException(TOKEN);
                        });
        failed.setDiagnostics(new FlowDiagnostics(lines::add, lines::add));
        try {
            failed.join(UUID, TOKEN, DIGEST);
            fail();
        } catch (IOException expected) {
        }
        String log = String.join("\n", lines);
        assertTrue(log.contains("result=FAILED"));
        assertFalse(log.contains(TOKEN));
    }
}
