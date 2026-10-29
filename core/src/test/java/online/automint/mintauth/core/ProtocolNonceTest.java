// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import static org.junit.Assert.*;

import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpServer;

import org.junit.Test;

import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

public class ProtocolNonceTest {
    @Test
    public void postNonceChallengeIsReadableAndRetriedWithFreshProof() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        List<JsonObject> claims = Collections.synchronizedList(new ArrayList<>());
        AtomicReference<Throwable> handlerFailure = new AtomicReference<>();
        server.createContext(
                "/device/code",
                exchange -> {
                    try {
                        byte[] incoming = read(exchange.getRequestBody());
                        assertEquals(
                                "synthetic-device",
                                Json.string(
                                        Json.object(
                                                new String(incoming, StandardCharsets.UTF_8),
                                                24576),
                                        "deviceName"));
                        String proof = exchange.getRequestHeaders().getFirst("DPoP");
                        JsonObject payload =
                                Json.object(
                                        new String(
                                                Crypto.unb64(proof.split("\\.")[1]),
                                                StandardCharsets.UTF_8),
                                        8192);
                        claims.add(payload);
                        boolean retry = claims.size() == 2;
                        String body = retry ? "{\"paired\":true}" : "{\"code\":\"USE_DPOP_NONCE\"}";
                        if (!retry) {
                            exchange.getResponseHeaders().set("DPoP-Nonce", "synthetic-nonce");
                            exchange.getResponseHeaders()
                                    .set("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\"");
                        }
                        byte[] out = body.getBytes(StandardCharsets.UTF_8);
                        exchange.getResponseHeaders().set("Content-Type", "application/json");
                        exchange.sendResponseHeaders(retry ? 200 : 401, out.length);
                        exchange.getResponseBody().write(out);
                    } catch (Throwable failure) {
                        handlerFailure.set(failure);
                        exchange.sendResponseHeaders(500, -1);
                    } finally {
                        exchange.close();
                    }
                });
        server.start();
        try {
            ProtocolClient client = localClient(server);
            KeyPair pair = Crypto.ecKey();
            Crypto.Signer signer =
                    Crypto.software(pair.getPrivate(), Crypto.publicJwk(pair.getPublic()));
            JsonObject response =
                    client.request(
                            "POST",
                            "device/code",
                            Json.obj("deviceName", "synthetic-device"),
                            null,
                            signer);
            assertNull(handlerFailure.get());
            assertTrue(response.get("paired").getAsBoolean());
            assertEquals(2, claims.size());
            assertFalse(claims.get(0).has("nonce"));
            assertEquals("synthetic-nonce", Json.string(claims.get(1), "nonce"));
            assertNotEquals(Json.string(claims.get(0), "jti"), Json.string(claims.get(1), "jti"));
            assertEquals(
                    "https://automint.online/api/mintauth/v1/device/code",
                    Json.string(claims.get(1), "htu"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    public void postAuthenticationErrorRetainsItsSpecificCode() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext(
                "/device/code",
                exchange -> {
                    try {
                        read(exchange.getRequestBody());
                        byte[] out =
                                "{\"code\":\"INVALID_GRANT\"}".getBytes(StandardCharsets.UTF_8);
                        exchange.getResponseHeaders().set("WWW-Authenticate", "DPoP");
                        exchange.sendResponseHeaders(401, out.length);
                        exchange.getResponseBody().write(out);
                    } finally {
                        exchange.close();
                    }
                });
        server.start();
        try {
            try {
                localClient(server)
                        .request("POST", "device/code", Json.obj("test", "synthetic"), null, null);
                fail("Expected authentication rejection");
            } catch (ProtocolClient.ApiException expected) {
                assertEquals(401, expected.status);
                assertEquals("INVALID_GRANT", expected.code);
            }
        } finally {
            server.stop(0);
        }
    }

    private static ProtocolClient localClient(HttpServer server) {
        return new ProtocolClient(
                (url, method) -> {
                    assertEquals("https://automint.online/api/mintauth/v1/device/code", url);
                    HttpURLConnection connection =
                            (HttpURLConnection)
                                    new URL(
                                                    "http://127.0.0.1:"
                                                            + server.getAddress().getPort()
                                                            + "/device/code")
                                            .openConnection();
                    connection.setRequestMethod(method);
                    connection.setInstanceFollowRedirects(false);
                    connection.setConnectTimeout(3000);
                    connection.setReadTimeout(3000);
                    return connection;
                });
    }

    private static byte[] read(java.io.InputStream input) throws java.io.IOException {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int n;
        while ((n = input.read(buffer)) != -1) {
            out.write(buffer, 0, n);
            if (out.size() > 24576) throw new java.io.IOException("TEST_REQUEST_LIMIT");
        }
        return out.toByteArray();
    }
}
