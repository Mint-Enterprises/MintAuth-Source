// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import static org.junit.Assert.*;

import com.google.gson.*;

import org.junit.Test;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;

public class WholeModDiagnosticsTest {
    private static final String SECRET = "PRIVATE_WHOLE_MOD_SENTINEL";

    private static String output(List<String> lines) {
        return String.join("\n", lines);
    }

    private static void noSecrets(List<String> lines, String... secrets) {
        assertFalse(output(lines).contains(SECRET));
        for (String secret : secrets) assertFalse(output(lines).contains(secret));
    }

    @Test
    public void vaultLifecycleAndFailedDecryptAreVisibleWithoutLoggingSavedSecrets()
            throws Exception {
        List<String> lines = new ArrayList<>();
        FlowDiagnostics trace = new FlowDiagnostics(lines::add, lines::add);
        Path root = Files.createTempDirectory(SECRET);
        SecurityTest.MemoryStore store = new SecurityTest.MemoryStore();
        String generation;
        try (Vault vault = new Vault(root, store)) {
            vault.setDiagnostics(trace);
            vault.unlock(null, false);
            generation = Json.string(vault.header(), "generation");
            vault.update(
                    data -> {
                        data.addProperty("ssid", SECRET);
                        return null;
                    });
            assertEquals(SECRET, Json.string(vault.read(), "ssid"));
        }
        Files.write(root.resolve("vault-" + generation + ".enc"), new byte[] {1, 2, 3});
        try (Vault vault = new Vault(root, store)) {
            vault.setDiagnostics(trace);
            try {
                vault.unlock(null, false);
                fail();
            } catch (Vault.Locked expected) {
            }
        }
        String text = output(lines);
        for (String step :
                new String[] {
                    "VAULT_UNLOCK",
                    "VAULT_TRANSACTION",
                    "VAULT_ENCRYPT",
                    "VAULT_COMMIT",
                    "VAULT_READ",
                    "VAULT_LOCK"
                }) assertTrue(step, text.contains("step=" + step));
        assertTrue(text.contains("step=VAULT_UNLOCK result=FAILED"));
        noSecrets(lines, generation, root.toString());
    }

    @Test
    public void leaseConflictMovementAndReceiptsDoNotExposeIdentifiers() throws Exception {
        List<String> lines = new ArrayList<>();
        FlowDiagnostics trace = new FlowDiagnostics(lines::add, lines::add);
        Path root = Files.createTempDirectory(SECRET);
        String account = "12345678123456781234567812345678";
        try (PlayLease first = new PlayLease(root);
                PlayLease second = new PlayLease(root)) {
            first.setDiagnostics(trace);
            second.setDiagnostics(trace);
            assertTrue(first.acquire(account));
            assertFalse(second.acquire(account));
            second.requestMove(account);
            assertTrue(first.moveRequested());
        }
        String generation = UUID.randomUUID().toString();
        InstanceRegistry first = new InstanceRegistry(root), second = new InstanceRegistry(root);
        first.setDiagnostics(trace);
        second.setDiagnostics(trace);
        first.report(generation, true);
        second.report(generation, false);
        assertFalse(first.allReported(generation));
        second.report(generation, true);
        assertTrue(first.allReported(generation));
        assertTrue(output(lines).contains("step=LEASE_ACQUIRE result=BLOCKED"));
        assertTrue(output(lines).contains("step=INSTANCE_RECEIPTS result=ALLOWED"));
        noSecrets(lines, account, generation, root.toString());
    }

    @Test
    public void unchangedTickDecisionsAndPreparationPhasesAreDeduplicated() {
        List<String> lines = new ArrayList<>();
        FlowDiagnostics trace = new FlowDiagnostics(lines::add, lines::add);
        for (int i = 0; i < 1000; i++)
            trace.state(FlowDiagnostics.Step.JOIN_GATE, FlowDiagnostics.Result.ALLOWED);
        assertEquals(1, lines.size());
        trace.state(FlowDiagnostics.Step.JOIN_GATE, FlowDiagnostics.Result.BLOCKED);
        assertEquals(2, lines.size());
        AccountPreparation attempt = new AccountPreparation(14, SECRET, trace);
        for (int i = 0; i < 1000; i++) attempt.update(AccountPreparation.Phase.CHECKING, SECRET);
        attempt.cancel();
        assertTrue(output(lines).contains("attempt=14 phase=CANCELLED"));
        assertEquals(5, lines.size());
        noSecrets(lines);
    }

    @Test
    public void syntheticSelectionApplicationAndLauncherRestorationAreTraced() throws Exception {
        List<String> lines = Collections.synchronizedList(new ArrayList<>());
        PreparationLifecycleTest.Bridge bridge =
                new PreparationLifecycleTest.Bridge() {
                    public void logDiagnostic(String line) {
                        lines.add(line);
                    }

                    public void logFailureDiagnostic(String line) {
                        lines.add(line);
                    }
                };
        try (PreparationLifecycleTest.Fixture fixture =
                new PreparationLifecycleTest.Fixture(
                        bridge, PreparationLifecycleTest.localProfile(), false)) {
            fixture.runtime.select(PreparationLifecycleTest.ID, false);
            Runnable apply = bridge.callbacks.poll(5, TimeUnit.SECONDS);
            assertNotNull(apply);
            apply.run();
            assertEquals(PreparationLifecycleTest.ID, fixture.runtime.playingAccountId());
            fixture.runtime.restoreLauncher();
            Runnable restore = bridge.callbacks.poll(5, TimeUnit.SECONDS);
            assertNotNull(restore);
            restore.run();
            assertNull(fixture.runtime.playingAccountId());
            for (String step :
                    new String[] {
                        "ACCOUNT_SELECT",
                        "ACCOUNT_SOURCE",
                        "IDENTITY_PREPARE",
                        "IDENTITY_APPLY",
                        "LAUNCHER_RESTORE"
                    }) assertTrue(step, output(lines).contains("step=" + step));
            noSecrets(
                    lines,
                    PreparationLifecycleTest.ID,
                    PreparationLifecycleTest.UUID,
                    "SyntheticUser",
                    "synthetic-test-token-never-sent-to-network");
        }
    }

    @Test
    public void updateAndCleanupRejectionPathsAreLoggedWithoutRecipeOrSignedData()
            throws Exception {
        List<String> lines = new ArrayList<>();
        FlowDiagnostics trace = new FlowDiagnostics(lines::add, lines::add);
        Path game = Files.createTempDirectory(SECRET);
        Files.createDirectory(game.resolve("mods"));
        Path jar = game.resolve("mods/test.jar");
        Files.write(jar, new byte[] {1});
        UpdateService service = new UpdateService("forge-1.8.9", game, jar, trace);
        JsonObject metadata = Json.obj("manifest", SECRET);
        metadata.addProperty("signature", SECRET);
        service.check(
                metadata,
                (key, path, maximum) -> {
                    fail();
                });
        Files.write(
                game.resolve(".mintauth-updates/state.json"),
                ("{\"pending\":\"" + SECRET + "\"}").getBytes(StandardCharsets.UTF_8));
        service.resume();
        service.cancel();
        try {
            CleanupVerifier.verify(SECRET, new JsonArray(), SECRET, SECRET, trace);
            fail();
        } catch (GeneralSecurityException expected) {
        }
        for (String step :
                new String[] {
                    "UPDATE_MANIFEST_VERIFY",
                    "UPDATE_CHECK",
                    "UPDATE_RESUME",
                    "UPDATE_CANCEL",
                    "CLEANUP_VERIFY"
                }) assertTrue(step, output(lines).contains("step=" + step + " result=FAILED"));
        noSecrets(lines, game.toString(), jar.toString());
    }

    @Test
    public void adapterEventsKeepFailureEmptyAndCancellationDistinct() {
        assertEquals(GameBridge.Progress.SUCCEEDED, GameBridge.completion(true, null));
        assertEquals(GameBridge.Progress.EMPTY, GameBridge.completion(false, null));
        assertEquals(
                GameBridge.Progress.FAILED,
                GameBridge.completion(true, new IllegalStateException(SECRET)));
        List<String> lines = new ArrayList<>();
        FlowDiagnostics trace = new FlowDiagnostics(lines::add, lines::add);
        trace.bridge(GameBridge.Stage.PROFILE_KEYS, GameBridge.Progress.FAILED, null);
        trace.bridge(GameBridge.Stage.KEY_FETCH, GameBridge.Progress.EMPTY, null);
        trace.bridge(GameBridge.Stage.KEY_FETCH, GameBridge.Progress.CANCELLED, null);
        trace.bridge(
                GameBridge.Stage.RESTRICTIONS,
                GameBridge.Progress.FAILED,
                new IllegalStateException(SECRET));
        assertTrue(output(lines).contains("step=MC_PROFILE_KEYS result=FAILED"));
        assertTrue(output(lines).contains("step=MC_KEY_FETCH result=EMPTY"));
        assertTrue(output(lines).contains("step=MC_KEY_FETCH result=CANCELLED"));
        noSecrets(lines);
    }

    @Test
    public void helperFailureAndBrokenLoggersCannotExposeInputsOrBreakVaultUse() throws Exception {
        PrintStream before = System.err;
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        try {
            System.setErr(new PrintStream(captured));
            UpdateInstaller.main(new String[] {SECRET, SECRET});
        } finally {
            System.setErr(before);
        }
        String text = new String(captured.toByteArray(), StandardCharsets.UTF_8);
        assertFalse(text.contains(SECRET));
        assertTrue(text.contains("step=UPDATE_HELPER result=FAILED"));
        FlowDiagnostics broken =
                new FlowDiagnostics(
                        line -> {
                            throw new IllegalStateException(SECRET);
                        },
                        line -> {
                            throw new IllegalStateException(SECRET);
                        });
        Path root = Files.createTempDirectory(SECRET);
        try (Vault vault = new Vault(root, new SecurityTest.MemoryStore())) {
            vault.setDiagnostics(broken);
            vault.unlock(null, false);
            vault.update(
                    data -> {
                        data.addProperty("value", true);
                        return null;
                    });
            assertTrue(vault.read().get("value").getAsBoolean());
        }
    }
}
