// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

public enum MultiplayerAccess {
    UNKNOWN,
    ALLOWED,
    DISABLED,
    BANNED;

    static MultiplayerAccess parse(JsonObject attributes, long now) {
        JsonElement scopes = attributes.get("bannedScopes");
        if (scopes != null && scopes.isJsonObject()) {
            JsonElement multiplayer = scopes.getAsJsonObject().get("MULTIPLAYER");
            if (multiplayer != null && multiplayer.isJsonObject()) {
                JsonElement expires = multiplayer.getAsJsonObject().get("expires");
                if (expires == null || expires.isJsonNull()) return BANNED;
                if (expires.isJsonPrimitive() && expires.getAsJsonPrimitive().isNumber()) {
                    if (expires.getAsLong() > now) return BANNED;
                } else if (expires.isJsonPrimitive() && expires.getAsJsonPrimitive().isString()) {
                    try {
                        if (java.time.Instant.parse(expires.getAsString()).toEpochMilli() > now)
                            return BANNED;
                    } catch (java.time.format.DateTimeParseException malformed) {
                        return UNKNOWN;
                    }
                } else return UNKNOWN;
            }
        }
        JsonElement privileges = attributes.get("privileges");
        if (privileges == null || !privileges.isJsonObject()) return UNKNOWN;
        JsonElement server = privileges.getAsJsonObject().get("multiplayerServer");
        if (server == null || !server.isJsonObject()) return UNKNOWN;
        JsonElement enabled = server.getAsJsonObject().get("enabled");
        if (enabled == null
                || !enabled.isJsonPrimitive()
                || !enabled.getAsJsonPrimitive().isBoolean()) return UNKNOWN;
        return enabled.getAsBoolean() ? ALLOWED : DISABLED;
    }

    public String restriction() {
        return this == DISABLED
                ? "Multiplayer is disabled in this account's Microsoft/Xbox privacy settings."
                        + " Singleplayer is available."
                : this == BANNED
                        ? "Minecraft reports a multiplayer ban for this account. Singleplayer is"
                                + " available."
                        : null;
    }
}
