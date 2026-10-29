// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import java.net.URI;
import java.util.concurrent.Executor;

final class AccountWebsiteAction {
    static final URI URL = URI.create(ProtocolClient.ORIGIN + "/dashboard/accounts?action=add");

    interface Opener {
        void open(URI url) throws Exception;
    }

    private final Executor executor;
    private final Opener opener;
    private final FlowDiagnostics trace;
    private long revision;
    private volatile boolean opening, attempted;
    private volatile String message;

    AccountWebsiteAction(Executor executor, Opener opener) {
        this(executor, opener, FlowDiagnostics.silent());
    }

    AccountWebsiteAction(Executor executor, Opener opener, FlowDiagnostics trace) {
        this.executor = executor;
        this.opener = opener;
        this.trace = trace;
    }

    synchronized void open() {
        trace.step(FlowDiagnostics.Step.WEBSITE_CLICK, FlowDiagnostics.Result.STARTED);
        if (opening) {
            trace.step(FlowDiagnostics.Step.WEBSITE_DISPATCH, FlowDiagnostics.Result.SKIPPED);
            return;
        }
        final long request = ++revision;
        opening = true;
        attempted = false;
        message = "Opening AutoMint in your browser...";
        try {
            executor.execute(
                    () -> {
                        try {
                            synchronized (this) {
                                if (request != revision) return;
                            }
                            trace.step(
                                    FlowDiagnostics.Step.WEBSITE_DISPATCH,
                                    FlowDiagnostics.Result.STARTED);
                            opener.open(URL);
                            trace.step(
                                    FlowDiagnostics.Step.WEBSITE_DISPATCH,
                                    FlowDiagnostics.Result.SUCCEEDED);
                            complete(
                                    request,
                                    "Continue in your browser. Add the account, then return here.");
                        } catch (Exception | LinkageError error) {
                            trace.failure(FlowDiagnostics.Step.WEBSITE_DISPATCH, error);
                            complete(
                                    request,
                                    "Could not open your browser. Choose Copy website link below.");
                        }
                    });
        } catch (RuntimeException | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.WEBSITE_DISPATCH, error);
            complete(request, "Browser could not start. Choose Copy website link below.");
        }
    }

    private synchronized void complete(long request, String notice) {
        if (request != revision) return;
        opening = false;
        attempted = true;
        message = notice;
    }

    synchronized void clear() {
        revision++;
        opening = false;
        attempted = false;
        message = null;
    }

    void copied(boolean success) {
        trace.step(
                FlowDiagnostics.Step.WEBSITE_COPY,
                success ? FlowDiagnostics.Result.SUCCEEDED : FlowDiagnostics.Result.FAILED);
        message =
                success
                        ? "Website link copied. Paste it into your browser."
                        : "Open automint.online/dashboard/accounts?action=add in your browser.";
    }

    boolean opening() {
        return opening;
    }

    boolean attempted() {
        return attempted;
    }

    String message() {
        return message;
    }
}
