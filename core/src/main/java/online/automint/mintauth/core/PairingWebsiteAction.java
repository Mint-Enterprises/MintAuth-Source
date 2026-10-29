// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import java.net.URI;
import java.util.concurrent.Executor;

final class PairingWebsiteAction {
    static final String PAGE = ProtocolClient.ORIGIN + "/mintauth/link";
    private final Executor executor;
    private final AccountWebsiteAction.Opener opener;
    private final java.util.function.Consumer<Throwable> failures;
    private final FlowDiagnostics trace;
    private long revision;
    private String code = "";
    private volatile boolean opening;
    private volatile String notice;

    PairingWebsiteAction(Executor executor, AccountWebsiteAction.Opener opener) {
        this(executor, opener, error -> {});
    }

    PairingWebsiteAction(
            Executor executor,
            AccountWebsiteAction.Opener opener,
            java.util.function.Consumer<Throwable> failures) {
        this(executor, opener, failures, FlowDiagnostics.silent());
    }

    PairingWebsiteAction(
            Executor executor,
            AccountWebsiteAction.Opener opener,
            java.util.function.Consumer<Throwable> failures,
            FlowDiagnostics trace) {
        this.executor = executor;
        this.opener = opener;
        this.failures = failures;
        this.trace = trace;
    }

    static URI uri(String code) {
        if (code == null || !code.matches("[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}"))
            throw new IllegalArgumentException("PAIRING_CODE_FORMAT");
        return URI.create(PAGE + "#code=" + code.replace("-", ""));
    }

    synchronized void begin(String value) {
        uri(value);
        trace.step(FlowDiagnostics.Step.PAIRING_READY, FlowDiagnostics.Result.SUCCEEDED);
        revision++;
        code = value;
        opening = false;
        notice = null;
    }

    synchronized void clear() {
        if (!code.isEmpty())
            trace.step(FlowDiagnostics.Step.BROWSER_CLEAR, FlowDiagnostics.Result.CANCELLED);
        revision++;
        code = "";
        opening = false;
        notice = null;
    }

    synchronized void open() {
        trace.step(FlowDiagnostics.Step.BROWSER_CLICK, FlowDiagnostics.Result.STARTED);
        if (opening || code.isEmpty()) {
            trace.step(
                    FlowDiagnostics.Step.BROWSER_QUEUED,
                    code.isEmpty() ? FlowDiagnostics.Result.EMPTY : FlowDiagnostics.Result.SKIPPED);
            return;
        }
        final URI target = uri(code);
        final long request = ++revision;
        opening = true;
        notice = "Opening AutoMint in your browser...";
        trace.step(FlowDiagnostics.Step.BROWSER_QUEUED, FlowDiagnostics.Result.QUEUED);
        try {
            executor.execute(
                    () -> {
                        try {
                            synchronized (this) {
                                if (request != revision) {
                                    trace.step(
                                            FlowDiagnostics.Step.BROWSER_DISPATCH,
                                            FlowDiagnostics.Result.CANCELLED);
                                    return;
                                }
                            }
                            trace.step(
                                    FlowDiagnostics.Step.BROWSER_DISPATCH,
                                    FlowDiagnostics.Result.STARTED);
                            opener.open(target);
                            trace.step(
                                    FlowDiagnostics.Step.BROWSER_DISPATCH,
                                    FlowDiagnostics.Result.SUCCEEDED);
                            complete(
                                    request,
                                    "Approve this device in your browser. Keep this page open.");
                        } catch (Exception | LinkageError error) {
                            trace.failure(FlowDiagnostics.Step.BROWSER_DISPATCH, error);
                            try {
                                failures.accept(error);
                            } catch (RuntimeException | LinkageError ignored) {
                            }
                            complete(
                                    request,
                                    "Browser did not open. Choose Copy link, or open"
                                            + " automint.online/mintauth/link and enter the code"
                                            + " above.");
                        }
                    });
        } catch (RuntimeException | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.BROWSER_QUEUED, error);
            complete(
                    request,
                    "Browser could not start. Choose Copy link, or enter the code on"
                            + " automint.online/mintauth/link.");
        }
    }

    private synchronized void complete(long request, String message) {
        if (request != revision) return;
        opening = false;
        notice = message;
    }

    synchronized String link() {
        return code.isEmpty() ? PAGE : uri(code).toASCIIString();
    }

    synchronized void copied(boolean success) {
        trace.step(
                FlowDiagnostics.Step.BROWSER_COPY,
                success ? FlowDiagnostics.Result.SUCCEEDED : FlowDiagnostics.Result.FAILED);
        notice =
                success
                        ? "Link copied. Paste it into your browser and approve this device."
                        : "Open automint.online/mintauth/link and enter the code above.";
    }

    boolean opening() {
        return opening;
    }

    String notice() {
        return notice;
    }
}
