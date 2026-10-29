// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import com.google.gson.JsonObject;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class MinecraftJoin {
    public enum Reason {
        PRIVILEGES,
        BANNED,
        INVALID_SESSION,
        RATE_LIMITED,
        UNAVAILABLE,
        REJECTED
    }

    public static final class Failure extends IOException {
        public final Reason reason;
        public final int status;

        Failure(Reason reason, int status) {
            super(message(reason));
            this.reason = reason;
            this.status = status;
        }
    }

    private final ProtocolClient.Connections connections;
    private FlowDiagnostics trace = FlowDiagnostics.silent();

    public MinecraftJoin() {
        this(
                (url, method) -> {
                    HttpURLConnection connection =
                            (HttpURLConnection) new URL(url).openConnection();
                    connection.setConnectTimeout(5000);
                    connection.setReadTimeout(10000);
                    connection.setRequestMethod(method);
                    connection.setRequestProperty("Accept", "application/json");
                    connection.setRequestProperty("Cookie", "");
                    connection.setRequestProperty("Cache-Control", "no-store");
                    connection.setRequestProperty("User-Agent", "MintAuth/1.0.0");
                    return connection;
                });
    }

    MinecraftJoin(ProtocolClient.Connections connections) {
        this.connections = connections;
    }

    void setDiagnostics(FlowDiagnostics trace) {
        this.trace = trace;
    }

    public void join(String uuid, String token, String serverHash) throws IOException {
        if (uuid == null
                || !uuid.matches("[a-fA-F0-9]{32}")
                || token == null
                || token.length() < 16
                || token.length() > 16384
                || serverHash == null
                || !serverHash.matches("-?[a-fA-F0-9]{1,40}"))
            throw new Failure(Reason.REJECTED, 0);
        trace.step(FlowDiagnostics.Step.MC_AUTHENTICATION, FlowDiagnostics.Result.STARTED);
        HttpURLConnection connection = null;
        try {
            connection =
                    connections.open(
                            "https://sessionserver.mojang.com/session/minecraft/join", "POST");
            connection.setInstanceFollowRedirects(false);
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json");
            JsonObject request = Json.obj("accessToken", token);
            request.addProperty("selectedProfile", uuid);
            request.addProperty("serverId", serverHash);
            byte[] bytes = Json.GSON.toJson(request).getBytes(StandardCharsets.UTF_8);
            try (OutputStream output = connection.getOutputStream()) {
                output.write(bytes);
            } finally {
                Arrays.fill(bytes, (byte) 0);
            }
            int status = connection.getResponseCode();
            if (status == 204) {
                trace.minecraftJoin(status, null);
                return;
            }
            String code = null;
            if (status == 403) {
                InputStream stream = connection.getErrorStream();
                if (stream != null)
                    try (InputStream input = stream;
                            ByteArrayOutputStream output = new ByteArrayOutputStream()) {
                        byte[] buffer = new byte[1024];
                        int count;
                        long deadline =
                                System.nanoTime()
                                        + java.util.concurrent.TimeUnit.SECONDS.toNanos(10);
                        while ((count = input.read(buffer)) != -1) {
                            if (output.size() + count > 8192 || System.nanoTime() > deadline)
                                throw new IOException("MC_JOIN_RESPONSE_LIMIT");
                            output.write(buffer, 0, count);
                        }
                        try {
                            code =
                                    Json.optional(
                                            Json.object(
                                                    new String(
                                                            output.toByteArray(),
                                                            StandardCharsets.UTF_8),
                                                    8192),
                                            "error");
                        } catch (RuntimeException malformed) {
                        }
                    }
            }
            Reason reason = reason(status, code);
            trace.minecraftJoin(status, reason);
            throw new Failure(reason, status);
        } catch (IOException | RuntimeException error) {
            if (!(error instanceof Failure))
                trace.failure(FlowDiagnostics.Step.MC_AUTHENTICATION, error);
            throw error;
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    static Reason reason(int status, String code) {
        if (status == 429) return Reason.RATE_LIMITED;
        if (status >= 500) return Reason.UNAVAILABLE;
        if (status == 401) return Reason.INVALID_SESSION;
        if (status == 403) {
            if ("InsufficientPrivilegesException".equals(code)) return Reason.PRIVILEGES;
            if ("UserBannedException".equals(code)) return Reason.BANNED;
            if ("InvalidCredentialsException".equals(code)
                    || "InvalidTokenException".equals(code)
                    || "ForbiddenOperationException".equals(code)) return Reason.INVALID_SESSION;
            if ("AuthenticationUnavailableException".equals(code)) return Reason.UNAVAILABLE;
        }
        return Reason.REJECTED;
    }

    private static String message(Reason reason) {
        switch (reason) {
            case PRIVILEGES:
                return "Minecraft denied multiplayer access for this session. Check Microsoft/Xbox"
                           + " multiplayer settings. If already allowed, wait and obtain a fresh"
                           + " SSID. [MC_PRIVILEGES]";
            case BANNED:
                return "Minecraft reports a multiplayer ban for this account. [MC_BANNED]";
            case INVALID_SESSION:
                return "Minecraft rejected this session. Select the account again or replace its"
                           + " SSID. [MC_SESSION]";
            case RATE_LIMITED:
                return "Minecraft is limiting login attempts. Wait before trying again."
                           + " [MC_RATE_LIMIT]";
            case UNAVAILABLE:
                return "Minecraft's authentication service is unavailable. Try again later."
                           + " [MC_AUTH_SERVICE]";
            default:
                return "Minecraft rejected this server login. See MintAuth's sanitized"
                           + " authentication log. [MC_REJECTED]";
        }
    }
}
