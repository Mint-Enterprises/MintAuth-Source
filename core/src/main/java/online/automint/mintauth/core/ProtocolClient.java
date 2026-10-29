// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import com.google.gson.JsonObject;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentHashMap;

public final class ProtocolClient {
    public static final String ORIGIN = "https://automint.online";
    private final ConcurrentHashMap<String, String> nonces = new ConcurrentHashMap<>();

    interface Connections {
        HttpURLConnection open(String url, String method) throws IOException;
    }

    private final Connections connections;
    private volatile FlowDiagnostics trace = FlowDiagnostics.silent();

    void setDiagnostics(FlowDiagnostics value) {
        trace = value;
    }

    public ProtocolClient() {
        this(ProtocolClient::connection);
    }

    ProtocolClient(Connections connections) {
        this.connections = connections;
    }

    public static final class ApiException extends IOException {
        public final String code;
        public final int status;

        ApiException(String code, int status) {
            super(code);
            this.code = code;
            this.status = status;
        }

        public boolean accessExpired() {
            return code.equals("MINTAUTH_ACCESS_EXPIRED");
        }

        public boolean grantLost() {
            return code.equals("MINTAUTH_REVOKED")
                    || code.equals("MINTAUTH_RELINK_REQUIRED")
                    || code.equals("MINTAUTH_DISABLED")
                    || code.equals("INVENTORY_FORBIDDEN");
        }

        public boolean authorityLost() {
            return code.equals("MINTAUTH_REVOKED")
                    || code.equals("MINTAUTH_RELINK_REQUIRED")
                    || code.equals("INVENTORY_FORBIDDEN")
                    || code.equals("SESSION_AUTHORITY_CHANGED")
                    || code.equals("SESSION_ACCESS_UNAVAILABLE")
                    || code.equals("MINTAUTH_DISABLED")
                    || code.equals("SESSION_CREDENTIALS_REJECTED")
                    || code.equals("ACCOUNT_UNAVAILABLE")
                    || code.equals("USE_MANAGED_ACCOUNT")
                    || code.equals("EXTERNAL_UNAVAILABLE")
                    || code.equals("EXTERNAL_HISTORY_CHECK_PENDING");
        }
    }

    private static String path(String path) {
        if (!path.matches("[A-Za-z0-9/_-]+(?:\\?locator=[A-Za-z0-9_-]{43})?"))
            throw new IllegalArgumentException("API_PATH");
        return ORIGIN + "/api/mintauth/v1/" + path;
    }

    private static HttpURLConnection connection(String url, String method) throws IOException {
        HttpURLConnection result = (HttpURLConnection) new URL(url).openConnection();
        result.setInstanceFollowRedirects(false);
        result.setConnectTimeout(5000);
        result.setReadTimeout(10000);
        result.setRequestMethod(method);
        result.setRequestProperty("Accept", "application/json");
        result.setRequestProperty("User-Agent", "MintAuth/1.0.0");
        result.setRequestProperty("Cache-Control", "no-store");
        result.setRequestProperty("Cookie", "");
        return result;
    }

    private static String read(InputStream stream, int max) throws IOException {
        if (stream == null) return "{}";
        try (InputStream input = stream;
                ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(15);
            byte[] buffer = new byte[4096];
            int size = 0, n;
            while ((n = input.read(buffer)) != -1) {
                if (System.nanoTime() > deadline) throw new IOException("RESPONSE_DEADLINE");
                size += n;
                if (size > max) throw new IOException("RESPONSE_LIMIT");
                output.write(buffer, 0, n);
            }
            return new String(output.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    public JsonObject request(
            String method,
            String endpoint,
            JsonObject body,
            String credential,
            Crypto.Signer signer)
            throws Exception {
        long request = trace.requestId();
        FlowDiagnostics.Route route = FlowDiagnostics.route(endpoint);
        trace.http(
                FlowDiagnostics.Step.HTTP_REQUEST,
                FlowDiagnostics.Result.STARTED,
                request,
                route,
                method,
                0);
        try {
            return requestInternal(method, endpoint, body, credential, signer, request, route);
        } catch (Exception | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.HTTP_REQUEST, error, request, route);
            throw error;
        }
    }

    private JsonObject requestInternal(
            String method,
            String endpoint,
            JsonObject body,
            String credential,
            Crypto.Signer signer,
            long request,
            FlowDiagnostics.Route route)
            throws Exception {
        String url = path(endpoint), proofUrl = url.split("\\?", 2)[0];
        String nonceId = signer == null ? "" : Json.GSON.toJson(signer.publicJwk());
        for (int attempt = 0; attempt < 2; attempt++) {
            trace.http(
                    FlowDiagnostics.Step.HTTP_PREPARE,
                    FlowDiagnostics.Result.STARTED,
                    request,
                    route,
                    method,
                    0);
            HttpURLConnection connection = connections.open(url, method);
            try {
                trace.http(
                        FlowDiagnostics.Step.HTTP_PREPARE,
                        FlowDiagnostics.Result.SUCCEEDED,
                        request,
                        route,
                        method,
                        0);
                if (credential != null)
                    connection.setRequestProperty("Authorization", "DPoP " + credential);
                if (signer != null) {
                    trace.http(
                            FlowDiagnostics.Step.HTTP_PROOF,
                            FlowDiagnostics.Result.STARTED,
                            request,
                            route,
                            method,
                            0);
                    connection.setRequestProperty(
                            "DPoP",
                            Crypto.proof(
                                    signer, method, proofUrl, credential, nonces.get(nonceId)));
                    trace.http(
                            FlowDiagnostics.Step.HTTP_PROOF,
                            FlowDiagnostics.Result.SUCCEEDED,
                            request,
                            route,
                            method,
                            0);
                }
                trace.http(
                        FlowDiagnostics.Step.HTTP_SEND,
                        FlowDiagnostics.Result.STARTED,
                        request,
                        route,
                        method,
                        0);
                if (body != null) {
                    byte[] payload = Json.GSON.toJson(body).getBytes(StandardCharsets.UTF_8);
                    if (payload.length > 24576) throw new IOException("REQUEST_LIMIT");
                    connection.setDoOutput(true);
                    connection.setRequestProperty("Content-Type", "application/json");

                    try (OutputStream output = connection.getOutputStream()) {
                        output.write(payload);
                    } finally {
                        java.util.Arrays.fill(payload, (byte) 0);
                    }
                }
                int status = connection.getResponseCode();
                trace.http(
                        FlowDiagnostics.Step.HTTP_RESPONSE,
                        FlowDiagnostics.Result.SUCCEEDED,
                        request,
                        route,
                        method,
                        status);
                trace.http(
                        FlowDiagnostics.Step.HTTP_PARSE,
                        FlowDiagnostics.Result.STARTED,
                        request,
                        route,
                        method,
                        status);
                String text =
                        read(
                                status >= 400
                                        ? connection.getErrorStream()
                                        : connection.getInputStream(),
                                240000);
                JsonObject response = Json.object(text, 240000);
                trace.http(
                        FlowDiagnostics.Step.HTTP_PARSE,
                        FlowDiagnostics.Result.SUCCEEDED,
                        request,
                        route,
                        method,
                        status);
                if (status >= 200 && status < 300) {
                    trace.http(
                            FlowDiagnostics.Step.HTTP_REQUEST,
                            FlowDiagnostics.Result.SUCCEEDED,
                            request,
                            route,
                            method,
                            status);
                    return response;
                }
                String code = Json.optional(response, "code");
                if (code == null || !code.matches("[A-Z_]{1,80}")) code = "REQUEST_FAILED";
                String nonce = connection.getHeaderField("DPoP-Nonce");
                if (attempt == 0
                        && signer != null
                        && code.equals("USE_DPOP_NONCE")
                        && nonce != null
                        && nonce.length() < 200) {
                    nonces.put(nonceId, nonce);
                    trace.http(
                            FlowDiagnostics.Step.HTTP_NONCE_RETRY,
                            FlowDiagnostics.Result.RETRYING,
                            request,
                            route,
                            method,
                            status);
                    continue;
                }
                throw new ApiException(code, status);
            } finally {
                connection.disconnect();
            }
        }
        throw new IOException("NONCE_RETRY_EXHAUSTED");
    }

    public void downloadUpdate(
            String key,
            java.nio.file.Path destination,
            int maximum,
            String credential,
            Crypto.Signer signer)
            throws Exception {
        long request = trace.requestId();
        trace.http(
                FlowDiagnostics.Step.UPDATE_DOWNLOAD,
                FlowDiagnostics.Result.STARTED,
                request,
                FlowDiagnostics.Route.UPDATES,
                "GET",
                0);
        try {
            downloadUpdateInternal(key, destination, maximum, credential, signer, request);
        } catch (Exception | LinkageError error) {
            trace.failure(
                    FlowDiagnostics.Step.UPDATE_DOWNLOAD,
                    error,
                    request,
                    FlowDiagnostics.Route.UPDATES);
            throw error;
        }
    }

    private void downloadUpdateInternal(
            String key,
            java.nio.file.Path destination,
            int maximum,
            String credential,
            Crypto.Signer signer,
            long request)
            throws Exception {
        if (!key.matches("forge189|fabric121|fabric263")
                || maximum < 1
                || maximum > ReleaseVerifier.MAX_JAR) throw new IOException("UPDATE_REQUEST");
        String url = path("updates/" + key), nonceId = Json.GSON.toJson(signer.publicJwk());
        for (int attempt = 0; attempt < 2; attempt++) {
            HttpURLConnection connection = connection(url, "GET");
            connection.setReadTimeout(15000);
            connection.setRequestProperty("Accept", "application/java-archive");
            connection.setRequestProperty("Authorization", "DPoP " + credential);
            connection.setRequestProperty(
                    "DPoP", Crypto.proof(signer, "GET", url, credential, nonces.get(nonceId)));
            try {
                int status = connection.getResponseCode();
                trace.http(
                        FlowDiagnostics.Step.HTTP_RESPONSE,
                        FlowDiagnostics.Result.SUCCEEDED,
                        request,
                        FlowDiagnostics.Route.UPDATES,
                        "GET",
                        status);
                if (status != 200) {
                    JsonObject error = Json.object(read(connection.getErrorStream(), 32768), 32768);
                    String code = Json.optional(error, "code"),
                            nonce = connection.getHeaderField("DPoP-Nonce");
                    if (code == null || !code.matches("[A-Z_]{1,80}")) code = "REQUEST_FAILED";
                    if (attempt == 0
                            && code.equals("USE_DPOP_NONCE")
                            && nonce != null
                            && nonce.length() < 200) {
                        nonces.put(nonceId, nonce);
                        trace.http(
                                FlowDiagnostics.Step.HTTP_NONCE_RETRY,
                                FlowDiagnostics.Result.RETRYING,
                                request,
                                FlowDiagnostics.Route.UPDATES,
                                "GET",
                                status);
                        continue;
                    }
                    throw new ApiException(code, status);
                }
                if (connection.getContentLengthLong() != maximum
                        || !"application/java-archive".equals(connection.getContentType()))
                    throw new IOException("UPDATE_RESPONSE");
                long deadline =
                        System.nanoTime() + java.util.concurrent.TimeUnit.MINUTES.toNanos(2);
                int total = 0, n;
                byte[] buffer = new byte[65536];
                try (InputStream input = connection.getInputStream();
                        OutputStream output =
                                java.nio.file.Files.newOutputStream(
                                        destination, java.nio.file.StandardOpenOption.CREATE_NEW)) {
                    while ((n = input.read(buffer)) != -1) {
                        total += n;
                        if (total > maximum || System.nanoTime() > deadline)
                            throw new IOException("UPDATE_LIMIT");
                        output.write(buffer, 0, n);
                    }
                }
                if (total != maximum) throw new IOException("UPDATE_TRUNCATED");
                trace.http(
                        FlowDiagnostics.Step.UPDATE_DOWNLOAD,
                        FlowDiagnostics.Result.SUCCEEDED,
                        request,
                        FlowDiagnostics.Route.UPDATES,
                        "GET",
                        200);
                return;
            } finally {
                connection.disconnect();
            }
        }
        throw new IOException("NONCE_RETRY_EXHAUSTED");
    }

    public interface Event {
        void receive(String type, JsonObject body) throws Exception;
    }

    private String eventLine(BufferedReader reader, long deadline) throws IOException {
        StringBuilder line = new StringBuilder();
        int c;
        while ((c = reader.read()) != -1) {
            if (System.nanoTime() > deadline) throw new IOException("EVENT_DEADLINE");
            if (c == '\n') return line.toString();
            if (c != '\r') line.append((char) c);
            if (line.length() > 8192) throw new IOException("EVENT_LIMIT");
        }
        return line.length() == 0 ? null : line.toString();
    }

    public void events(String credential, Crypto.Signer signer, Event callback) throws Exception {
        long request = trace.requestId();
        trace.http(
                FlowDiagnostics.Step.EVENT_STREAM,
                FlowDiagnostics.Result.STARTED,
                request,
                FlowDiagnostics.Route.EVENTS,
                "GET",
                0);
        try {
            eventsInternal(credential, signer, callback, request);
        } catch (Exception | LinkageError error) {
            trace.failure(
                    FlowDiagnostics.Step.EVENT_STREAM,
                    error,
                    request,
                    FlowDiagnostics.Route.EVENTS);
            throw error;
        }
    }

    private void eventsInternal(
            String credential, Crypto.Signer signer, Event callback, long request)
            throws Exception {
        String url = path("events");
        HttpURLConnection connection = connection(url, "GET");
        connection.setRequestProperty("Accept", "text/event-stream");
        connection.setRequestProperty("Authorization", "DPoP " + credential);
        connection.setRequestProperty(
                "DPoP",
                Crypto.proof(
                        signer,
                        "GET",
                        url,
                        credential,
                        nonces.get(Json.GSON.toJson(signer.publicJwk()))));
        try {
            int status = connection.getResponseCode();
            trace.http(
                    FlowDiagnostics.Step.HTTP_RESPONSE,
                    FlowDiagnostics.Result.SUCCEEDED,
                    request,
                    FlowDiagnostics.Route.EVENTS,
                    "GET",
                    status);
            if (status != 200) throw new ApiException("EVENT_STREAM_UNAVAILABLE", status);
            trace.http(
                    FlowDiagnostics.Step.EVENT_STREAM,
                    FlowDiagnostics.Result.SUCCEEDED,
                    request,
                    FlowDiagnostics.Route.EVENTS,
                    "GET",
                    status);
            try (BufferedReader input =
                    new BufferedReader(
                            new InputStreamReader(
                                    connection.getInputStream(), StandardCharsets.UTF_8))) {
                String type = "message", data = null, line;
                int total = 0;
                long deadline =
                        System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(65);
                while ((line = eventLine(input, deadline)) != null) {
                    if ((total += line.length()) > 1024 * 1024)
                        throw new IOException("EVENT_LIMIT");
                    if (line.startsWith("event: ")) type = line.substring(7);
                    else if (line.startsWith("data: ")) data = line.substring(6);
                    else if (line.isEmpty() && data != null) {
                        trace.step(
                                FlowDiagnostics.Step.EVENT_RECEIVED,
                                FlowDiagnostics.Result.SUCCEEDED);
                        callback.receive(type, Json.object(data, 8192));
                        data = null;
                        type = "message";
                    }
                }
            }
        } finally {
            connection.disconnect();
        }
    }

    public MultiplayerAccess multiplayerAccess(String ssid) throws IOException {
        long request = trace.requestId();
        trace.http(
                FlowDiagnostics.Step.MC_RESTRICTIONS,
                FlowDiagnostics.Result.STARTED,
                request,
                FlowDiagnostics.Route.MINECRAFT_PERMISSIONS,
                "GET",
                0);
        HttpURLConnection connection = null;
        try {
            connection =
                    connections.open("https://api.minecraftservices.com/player/attributes", "GET");
            connection.setInstanceFollowRedirects(false);
            connection.setRequestProperty("Authorization", "Bearer " + ssid);
            int status = connection.getResponseCode();
            trace.http(
                    FlowDiagnostics.Step.HTTP_RESPONSE,
                    FlowDiagnostics.Result.SUCCEEDED,
                    request,
                    FlowDiagnostics.Route.MINECRAFT_PERMISSIONS,
                    "GET",
                    status);
            if (status == 401) throw new ApiException("EXTERNAL_TOKEN_REJECTED", status);
            if (status != 200) throw new IOException("MINECRAFT_PERMISSIONS_UNAVAILABLE");
            MultiplayerAccess access =
                    MultiplayerAccess.parse(
                            Json.object(read(connection.getInputStream(), 32768), 32768),
                            System.currentTimeMillis());
            trace.multiplayer(access);
            return access;
        } catch (IOException | RuntimeException | LinkageError error) {
            trace.failure(
                    FlowDiagnostics.Step.MC_RESTRICTIONS,
                    error,
                    request,
                    FlowDiagnostics.Route.MINECRAFT_PERMISSIONS);
            throw error;
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    public JsonObject profile(String ssid) throws IOException {
        long request = trace.requestId();
        trace.http(
                FlowDiagnostics.Step.PROFILE_CHECK,
                FlowDiagnostics.Result.STARTED,
                request,
                FlowDiagnostics.Route.MINECRAFT_PROFILE,
                "GET",
                0);
        try {
            JsonObject result = profileInternal(ssid, request);
            trace.http(
                    FlowDiagnostics.Step.PROFILE_CHECK,
                    FlowDiagnostics.Result.SUCCEEDED,
                    request,
                    FlowDiagnostics.Route.MINECRAFT_PROFILE,
                    "GET",
                    200);
            return result;
        } catch (IOException | RuntimeException | LinkageError error) {
            trace.failure(
                    FlowDiagnostics.Step.PROFILE_CHECK,
                    error,
                    request,
                    FlowDiagnostics.Route.MINECRAFT_PROFILE);
            throw error;
        }
    }

    private JsonObject profileInternal(String ssid, long request) throws IOException {
        HttpURLConnection connection =
                connections.open("https://api.minecraftservices.com/minecraft/profile", "GET");
        connection.setRequestProperty("Authorization", "Bearer " + ssid);
        try {
            int status = connection.getResponseCode();
            trace.http(
                    FlowDiagnostics.Step.HTTP_RESPONSE,
                    FlowDiagnostics.Result.SUCCEEDED,
                    request,
                    FlowDiagnostics.Route.MINECRAFT_PROFILE,
                    "GET",
                    status);
            if (status == 401 || status == 403)
                throw new ApiException("EXTERNAL_TOKEN_REJECTED", status);
            if (status != 200) throw new ApiException("MINECRAFT_UNAVAILABLE", 503);
            JsonObject profile = Json.object(read(connection.getInputStream(), 32768), 32768);
            if (!Json.string(profile, "id").matches("[a-fA-F0-9]{32}")
                    || !Json.string(profile, "name").matches("[A-Za-z0-9_]{1,16}"))
                throw new IOException("PROFILE_INVALID");
            return profile;
        } finally {
            connection.disconnect();
        }
    }
}
