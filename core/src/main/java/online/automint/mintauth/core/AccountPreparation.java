// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.concurrent.CancellationException;

public final class AccountPreparation {
    public enum Phase {
        QUEUED,
        CHECKING,
        PREPARING,
        APPLYING,
        READY,
        FAILED,
        CANCELLED,
        MOVE;

        public boolean terminal() {
            return this == READY || this == FAILED || this == CANCELLED || this == MOVE;
        }
    }

    public static final class Snapshot {
        public final Phase phase;
        public final String message;

        private Snapshot(Phase phase, String message) {
            this.phase = phase;
            this.message = message;
        }
    }

    final long revision;
    public final String accountId;
    private final FlowDiagnostics trace;
    private volatile Snapshot state =
            new Snapshot(Phase.QUEUED, "Waiting to start account preparation...");

    AccountPreparation(long revision, String accountId) {
        this(revision, accountId, FlowDiagnostics.silent());
    }

    AccountPreparation(long revision, String accountId, FlowDiagnostics trace) {
        this.revision = revision;
        this.accountId = accountId;
        this.trace = trace;
        trace.preparation(revision, Phase.QUEUED);
    }

    public Snapshot snapshot() {
        return state;
    }

    synchronized void update(Phase phase, String message) {
        if (!state.phase.terminal()) {
            state = new Snapshot(phase, message);
            trace.preparation(revision, phase);
        }
    }

    void cancel() {
        update(Phase.CANCELLED, "Account preparation cancelled.");
    }

    void checkCurrent(long currentRevision, boolean closed) {
        if (revision != currentRevision || closed || state.phase == Phase.CANCELLED)
            throw new CancellationException();
    }

    static String failureMessage(Throwable error) {
        if (error instanceof ProtocolClient.ApiException) {
            ProtocolClient.ApiException api = (ProtocolClient.ApiException) error;
            if (api.grantLost())
                return "Your AutoMint link is unavailable. Link again to continue.";
            if (api.authorityLost())
                return "You no longer have access to this account. Refresh your accounts or choose"
                        + " another.";
            if (api.code.equals("SESSION_REQUEST_COOLDOWN"))
                return "A fresh check has a five-minute cooldown. Wait before trying again.";
            if (api.code.equals("SESSION_REQUEST_IN_FLIGHT"))
                return "Mint is busy checking accounts. Try again shortly.";
            if (api.code.equals("RATE_LIMITED"))
                return "Mint is limiting account checks. Wait a few minutes, then try again.";
            if (api.code.equals("EXTERNAL_TOKEN_REJECTED"))
                return "This SSID was rejected. Try this Mint account again, or replace an external"
                        + " SSID.";
            if (api.code.equals("SESSION_CHECK_UNAVAILABLE"))
                return "Mint could not get a playable session. Try again later.";
            return "Mint could not prepare this account. Try again, or choose another account.";
        }
        if (error instanceof SocketTimeoutException)
            return "The connection timed out. Check your internet connection, then try again.";
        if (error instanceof java.net.ConnectException
                || error instanceof java.net.UnknownHostException)
            return "Could not reach AutoMint. Check your internet connection, then try again.";
        if (error instanceof IOException)
            return "Could not finish preparing the account. Try again, or choose another account.";
        return "Could not switch to this account. Try again, or choose another account.";
    }
}
