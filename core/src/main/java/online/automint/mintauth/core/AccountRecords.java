// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.Objects;
import java.util.UUID;

final class AccountRecords {
    private AccountRecords() {}

    private static final String[] LOCAL_SESSION_FIELDS = {
        "ssid",
        "offlineUntil",
        "checkedAt",
        "authorityStamp",
        "sessionRevision",
        "multiplayerRevision",
        "tokenCheckedAt",
        "providerCheckedAt",
        "knownExpiresAt",
        "rejectedTokenHash"
    };

    static boolean onMint(JsonObject record) {
        String source = Json.optional(record, "source");
        return "MANAGED".equals(source) || "CLOUD".equals(source);
    }

    static boolean locallyRemoved(JsonObject record) {
        return record.has("localRemoved");
    }

    static boolean canRestore(JsonObject record) {
        return record != null
                && !record.has("hidden")
                && !locallyRemoved(record)
                && !"DELETED".equals(Json.optional(record, "status"));
    }

    static void removeLocalCopy(JsonObject record, boolean everywhere) {
        record.addProperty("deviceRevision", UUID.randomUUID().toString());
        record.addProperty("localRemoved", true);
        for (String field : LOCAL_SESSION_FIELDS) record.remove(field);
        if (onMint(record) && !everywhere && !"DELETED".equals(Json.optional(record, "status"))) {
            record.remove("hidden");
        } else {
            record.addProperty("hidden", true);
            record.addProperty(
                    "status",
                    everywhere || "DELETED".equals(Json.optional(record, "status"))
                            ? "DELETED"
                            : "UNAVAILABLE");
        }
    }

    static JsonObject mergeRemote(JsonObject old, JsonObject remote, String grantId) {
        JsonObject updated = remote.deepCopy();
        updated.addProperty(
                "source", "EXTERNAL".equals(Json.string(remote, "kind")) ? "CLOUD" : "MANAGED");
        updated.addProperty("grantId", grantId);
        if (old != null) {
            if (old.has("deviceRevision")) updated.add("deviceRevision", old.get("deviceRevision"));
            if (locallyRemoved(old) || old.has("hidden")) {
                updated.addProperty("localRemoved", true);
                if (!updated.has("deviceRevision"))
                    updated.addProperty("deviceRevision", UUID.randomUUID().toString());
            }
            if ("DELETED".equals(Json.optional(old, "status")))
                updated.addProperty("status", "DELETED");
            boolean same =
                    Objects.equals(old.get("revision"), updated.get("revision"))
                            && Objects.equals(old.get("uuid"), updated.get("uuid"))
                            && Objects.equals(old.get("source"), updated.get("source"))
                            && Objects.equals(old.get("grantId"), updated.get("grantId"));
            if (same && !locallyRemoved(updated))
                for (String field : LOCAL_SESSION_FIELDS)
                    if (old.has(field)) updated.add(field, old.get(field));
        }
        if (locallyRemoved(updated))
            for (String field : LOCAL_SESSION_FIELDS) updated.remove(field);
        if ("DELETED".equals(Json.optional(updated, "status"))) {
            for (String field : LOCAL_SESSION_FIELDS) updated.remove(field);
            updated.addProperty("hidden", true);
        }
        return updated;
    }

    static boolean matchesPrepared(JsonObject data, String id, JsonObject prepared) {
        if (!data.has("accounts")) return false;
        JsonObject accounts = data.getAsJsonObject("accounts");
        JsonObject current = accounts.has(id) ? accounts.getAsJsonObject(id) : null;
        if (current == null
                || current.has("hidden")
                || locallyRemoved(current)
                || "DELETED".equals(Json.optional(current, "status"))) return false;
        for (String field :
                new String[] {
                    "uuid",
                    "source",
                    "revision",
                    "deviceRevision",
                    "grantId",
                    "ssid",
                    "context",
                    "authorityStamp",
                    "sessionRevision",
                    "multiplayerRevision",
                    "rejectedTokenHash",
                    "status"
                }) if (!Objects.equals(current.get(field), prepared.get(field))) return false;
        return true;
    }

    static boolean saveCloudCopy(
            JsonObject data,
            String localId,
            JsonObject expected,
            JsonObject remote,
            String grantId) {
        JsonObject entries = data.getAsJsonObject("accounts");
        JsonObject local = entries.has(localId) ? entries.getAsJsonObject(localId) : null;
        if (local == null
                || !"LOCAL".equals(Json.optional(local, "source"))
                || local.has("hidden")
                || locallyRemoved(local)) return false;
        for (String field : new String[] {"revision", "deviceRevision", "uuid", "ssid"})
            if (!Objects.equals(local.get(field), expected.get(field))) return false;
        String remoteId = Json.string(remote, "id");
        if (remoteId.equals(localId)
                || !AccountGroups.same(Json.string(local, "uuid"), Json.string(remote, "uuid")))
            return false;
        JsonObject old = entries.has(remoteId) ? entries.getAsJsonObject(remoteId) : null;
        if (old != null
                && ("DELETED".equals(Json.optional(old, "status"))
                        || old.has("localRemoved")
                        || old.get("revision").getAsLong() > remote.get("revision").getAsLong()))
            return false;
        entries.add(remoteId, mergeRemote(old, remote, grantId));
        local.addProperty("cloudCopyId", remoteId);
        local.add("syncedLocalRevision", local.get("revision"));
        return true;
    }

    static void applyCloudTombstones(JsonObject data) {
        JsonObject entries = data.getAsJsonObject("accounts");
        if (entries == null) return;
        for (java.util.Map.Entry<String, JsonElement> item : entries.entrySet()) {
            JsonObject local = item.getValue().getAsJsonObject();
            String copy = Json.optional(local, "cloudCopyId");
            if (copy == null
                    || !"LOCAL".equals(Json.optional(local, "source"))
                    || !Objects.equals(local.get("revision"), local.get("syncedLocalRevision")))
                continue;
            JsonObject cloud = entries.has(copy) ? entries.getAsJsonObject(copy) : null;
            if (cloud != null && "DELETED".equals(Json.optional(cloud, "status")))
                removeLocalCopy(local, true);
        }
    }

    static boolean needsSync(JsonObject entry) {
        return "LOCAL".equals(Json.optional(entry, "source"))
                && entry.has("ssid")
                && !entry.has("hidden")
                && !locallyRemoved(entry)
                && (!entry.has("syncedLocalRevision")
                        || !Objects.equals(
                                entry.get("revision"), entry.get("syncedLocalRevision")));
    }

    static boolean commitPrepared(
            JsonObject data,
            String id,
            JsonElement expectedRevision,
            JsonObject prepared,
            boolean userSelected) {
        if (!data.has("accounts")) return false;
        JsonObject accounts = data.getAsJsonObject("accounts");
        JsonObject current = accounts.has(id) ? accounts.getAsJsonObject(id) : null;
        if (current == null
                || current.has("hidden")
                || "DELETED".equals(Json.optional(current, "status"))
                || locallyRemoved(current) && !userSelected
                || !Objects.equals(current.get("deviceRevision"), prepared.get("deviceRevision"))
                || !Objects.equals(current.get("revision"), expectedRevision)
                || !Objects.equals(current.get("uuid"), prepared.get("uuid"))
                || !Objects.equals(current.get("source"), prepared.get("source"))
                || !Objects.equals(current.get("grantId"), prepared.get("grantId"))) return false;
        JsonObject next = prepared.deepCopy();
        for (String field : new String[] {"cloudCopyId", "syncedLocalRevision"})
            if (current.has(field)) next.add(field, current.get(field));
        next.remove("localRemoved");
        accounts.add(id, next);
        return true;
    }

    static boolean commitPrepared(
            JsonObject data, String id, JsonElement expectedRevision, JsonObject prepared) {
        return commitPrepared(data, id, expectedRevision, prepared, false);
    }
}
