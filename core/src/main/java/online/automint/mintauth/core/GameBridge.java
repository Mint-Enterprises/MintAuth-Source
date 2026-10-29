// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

public interface GameBridge {
    enum Stage {
        AUTHENTICATION,
        PREPARE,
        SERVICES,
        RESTRICTIONS,
        PROFILE,
        PROFILE_KEYS,
        SOCIAL,
        REPORTING,
        TELEMETRY,
        CONNECTION,
        SESSION,
        LAUNCHER,
        KEY_FETCH,
        KEY_CLEAR
    }

    enum Progress {
        STARTED,
        SUCCEEDED,
        FAILED,
        CANCELLED,
        EMPTY
    }

    static Progress completion(boolean present, Throwable error) {
        return error != null ? Progress.FAILED : present ? Progress.SUCCEEDED : Progress.EMPTY;
    }

    interface Diagnostics {
        void event(Stage stage, Progress progress, Throwable error);
    }

    default void setDiagnostics(Diagnostics diagnostics) {}

    final class Identity {
        public final String uuid, ign;
        private final String token;

        public Identity(String uuid, String ign, String token) {
            if (!uuid.matches("[a-fA-F0-9]{32}")
                    || !ign.matches("[A-Za-z0-9_]{1,16}")
                    || token.length() < 16) throw new IllegalArgumentException("IDENTITY_INVALID");
            this.uuid = uuid;
            this.ign = ign;
            this.token = token;
        }

        public String token() {
            return token;
        }

        public String fingerprint() {
            return uuid + ":" + Crypto.tokenHash(token);
        }

        @Override
        public String toString() {
            return "MintAuth identity [redacted]";
        }
    }

    default void logDiagnostic(String line) {
        System.out.println(line);
    }

    default void logFailureDiagnostic(String line) {
        logDiagnostic(line);
    }

    default void openWebsite(java.net.URI uri) throws Exception {
        java.awt.Desktop.getDesktop().browse(uri);
    }

    default void copyWebsiteLink(String link) {
        java.awt.Toolkit.getDefaultToolkit()
                .getSystemClipboard()
                .setContents(new java.awt.datatransfer.StringSelection(link), null);
    }

    void onClient(Runnable action);

    boolean worldOpen();

    default boolean multiplayerWorldOpen() { return false; }

    String currentFingerprint();

    void install(Identity identity) throws Exception;

    default Object prepare(Identity identity) throws Exception {
        return null;
    }

    default String preparationWarning(Object prepared) {
        return null;
    }

    default void installPrepared(Identity identity, Object prepared) throws Exception {
        install(identity);
    }

    void restoreLauncher() throws Exception;

    void leaveWorld(String reason, Runnable after);

    void connect(String originalDestination);
}
