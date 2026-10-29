// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import java.net.*;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.net.ssl.SSLException;

final class OperationFailures {
    enum Reason {
        NATIVE_RUNTIME,
        TLS,
        DNS,
        TIMEOUT,
        NETWORK,
        SERVER,
        REJECTED,
        KEYSTORE,
        SIGNING_KEY,
        BROWSER,
        DATA_FORMAT,
        OTHER
    }

    private OperationFailures() {}

    static Reason reason(Throwable error) {
        Reason fallback = Reason.OTHER;
        for (int depth = 0; error != null && depth < 8; depth++, error = error.getCause()) {
            if (error instanceof LinkageError) return Reason.NATIVE_RUNTIME;
            if (error instanceof java.io.IOException
                    && Arrays.asList(
                                    "NATIVE_RUNTIME_SOURCE",
                                    "NATIVE_RUNTIME_DEPENDENCY",
                                    "NATIVE_RUNTIME_VERSION",
                                    "NATIVE_RUNTIME_UNAVAILABLE")
                            .contains(error.getMessage())) return Reason.NATIVE_RUNTIME;
            if (error instanceof SSLException
                    || error instanceof java.security.cert.CertificateException) return Reason.TLS;
            if (error instanceof UnknownHostException) return Reason.DNS;
            if (error instanceof SocketTimeoutException
                    || error instanceof java.util.concurrent.TimeoutException)
                return Reason.TIMEOUT;
            if (error instanceof ConnectException) return Reason.NETWORK;
            if (error instanceof java.awt.HeadlessException) return Reason.BROWSER;
            if (error instanceof ProtocolClient.ApiException)
                return ((ProtocolClient.ApiException) error).status >= 500
                        ? Reason.SERVER
                        : Reason.REJECTED;
            if (error instanceof Vault.Locked) fallback = Reason.KEYSTORE;
            else if (error instanceof GeneralSecurityException && fallback == Reason.OTHER)
                fallback = Reason.SIGNING_KEY;
            else if (error instanceof com.google.gson.JsonParseException
                    && fallback == Reason.OTHER) fallback = Reason.DATA_FORMAT;
        }
        return fallback;
    }

    static String message(Throwable error) {
        switch (reason(error)) {
            case NATIVE_RUNTIME:
                return "MintAuth's native security support could not load. Use the latest official"
                        + " JAR and try again. [NATIVE]";
            case TLS:
                return "Java could not establish a secure connection to AutoMint. Check this"
                        + " instance's Java installation. [TLS]";
            case DNS:
                return "AutoMint's address could not be resolved. Check your connection or DNS,"
                        + " then retry. [DNS]";
            case TIMEOUT:
                return "The request timed out. Try again. [TIMEOUT]";
            case NETWORK:
                return "Could not connect to AutoMint. Check your connection and try again."
                        + " [NETWORK]";
            case SERVER:
                return "AutoMint could not complete the request. Try again shortly. [SERVER]";
            case REJECTED:
                return "AutoMint rejected this request. Try linking again. [REJECTED]";
            case KEYSTORE:
                return "Secure storage is unavailable. Unlock your system key storage and try"
                        + " again. [KEYSTORE]";
            case SIGNING_KEY:
                return "This device's signing key is unavailable. Unlock your system key storage"
                        + " and try again. [SIGNING_KEY]";
            case BROWSER:
                return "The browser could not open. Open AutoMint's linking page and enter the code"
                        + " shown here. [BROWSER]";
            case DATA_FORMAT:
                return "MintAuth could not read the returned data. Try again. [DATA_FORMAT]";
            default:
                return "MintAuth could not complete this step. Try again. [REQUEST]";
        }
    }
}
