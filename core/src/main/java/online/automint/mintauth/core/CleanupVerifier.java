// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import com.google.gson.*;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

public final class CleanupVerifier {
    private CleanupVerifier() {}

    static JsonObject verify(
            String jwt,
            JsonArray trustedKeys,
            String deviceId,
            String generation,
            FlowDiagnostics trace)
            throws GeneralSecurityException {
        trace.step(FlowDiagnostics.Step.CLEANUP_VERIFY, FlowDiagnostics.Result.STARTED);
        try {
            JsonObject result = verify(jwt, trustedKeys, deviceId, generation);
            trace.step(FlowDiagnostics.Step.CLEANUP_VERIFY, FlowDiagnostics.Result.SUCCEEDED);
            return result;
        } catch (GeneralSecurityException | RuntimeException | LinkageError error) {
            trace.failure(FlowDiagnostics.Step.CLEANUP_VERIFY, error);
            throw error;
        }
    }

    public static JsonObject verify(
            String jwt, JsonArray trustedKeys, String deviceId, String generation)
            throws GeneralSecurityException {
        if (jwt == null || jwt.length() > 8192)
            throw new GeneralSecurityException("CLEANUP_INVALID");
        String[] parts = jwt.split("\\.", -1);
        if (parts.length != 3) throw new GeneralSecurityException("CLEANUP_INVALID");
        try {
            JsonObject header =
                    Json.object(new String(Crypto.unb64(parts[0]), StandardCharsets.UTF_8), 2048);
            if (!Json.string(header, "alg").equals("ES256")
                    || !Json.string(header, "typ").equals("mintauth-cleanup+jwt"))
                throw new GeneralSecurityException("CLEANUP_ALGORITHM");
            PublicKey key = null;
            for (JsonElement element : trustedKeys) {
                JsonObject jwk = element.getAsJsonObject();
                if (Json.string(header, "kid").equals(Json.optional(jwk, "kid")))
                    key = Crypto.publicKey(jwk);
            }
            if (key == null) throw new GeneralSecurityException("CLEANUP_KEY_UNKNOWN");
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initVerify(key);
            signature.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
            if (!signature.verify(Crypto.derSignature(Crypto.unb64(parts[2]))))
                throw new GeneralSecurityException("CLEANUP_SIGNATURE");
            JsonObject command =
                    Json.object(new String(Crypto.unb64(parts[1]), StandardCharsets.UTF_8), 4096);
            if (command.get("version").getAsInt() != 1
                    || !Json.string(command, "action").equals("CLEAR_MINTAUTH")
                    || !Json.string(command, "iss").equals("mintauth")
                    || !Json.string(command, "aud").equals("mintauth-cleanup-v1")
                    || !Json.string(command, "deviceId").equals(deviceId)
                    || !Json.string(command, "vaultGeneration").equals(generation))
                throw new GeneralSecurityException("CLEANUP_BINDING");
            UUID.fromString(Json.string(command, "commandId"));
            UUID.fromString(generation);
            UUID.fromString(deviceId);
            return command;
        } catch (GeneralSecurityException e) {
            throw e;
        } catch (Exception e) {
            throw new GeneralSecurityException("CLEANUP_INVALID");
        }
    }
}
