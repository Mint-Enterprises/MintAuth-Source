// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import java.util.*;

final class AccountGroups {
    private AccountGroups() {}

    static String identity(String uuid) {
        if (uuid == null) return null;
        String normalized = uuid.replace("-", "").toLowerCase(Locale.ROOT);
        return normalized.matches("[a-f0-9]{32}") ? normalized : null;
    }

    static boolean same(String a, String b) {
        String identity = identity(a);
        return identity != null && identity.equals(identity(b));
    }

    static boolean available(MintAuthRuntime.AccountView a) {
        return a.status == null
                || "VALID".equals(a.status)
                || "AVAILABLE".equals(a.status)
                || !"EXTERNAL".equals(a.kind) && "EXPIRED_REJECTED".equals(a.status);
    }

    private static int rank(MintAuthRuntime.AccountView a) {
        if (a.onAutoMint && "OWNED".equals(a.kind)) return 0;
        if (a.onAutoMint && "TEMPORARY".equals(a.kind)) return 10;
        if (a.cloud && "MANAGED".equals(a.status)) return 20;
        return (available(a) ? 30 : 50) + (a.cloud ? 0 : 1);
    }

    static List<MintAuthRuntime.AccountView> cards(List<MintAuthRuntime.AccountView> entries) {
        Map<String, MintAuthRuntime.AccountView> preferred = new LinkedHashMap<>();
        for (MintAuthRuntime.AccountView entry : entries) {
            String uuid = identity(entry.uuid);
            String key = uuid == null ? "record:" + entry.id : "uuid:" + uuid;
            MintAuthRuntime.AccountView old = preferred.get(key);
            if (old == null || rank(entry) < rank(old)) preferred.put(key, entry);
        }
        return Collections.unmodifiableList(new ArrayList<>(preferred.values()));
    }

    static List<MintAuthRuntime.AccountView> sources(
            List<MintAuthRuntime.AccountView> entries, String uuid) {
        List<MintAuthRuntime.AccountView> sources = new ArrayList<>();
        for (MintAuthRuntime.AccountView entry : entries)
            if (same(uuid, entry.uuid)) sources.add(entry);
        sources.sort(Comparator.comparingInt(AccountGroups::rank));
        return Collections.unmodifiableList(sources);
    }
}
