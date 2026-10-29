// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import static org.junit.Assert.*;

import com.google.gson.JsonObject;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;

public class UpdateInstallerFailureTest {
    @Test
    public void failedHelperReportsFailureWithoutTerminatingItsHost() throws Exception {
        Path game = Files.createTempDirectory("mintauth-helper-failure");
        Path mods = Files.createDirectory(game.resolve("mods"));
        Path work = Files.createDirectory(game.resolve(".mintauth-updates"));
        Path stage = Files.createDirectory(work.resolve("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        JsonObject request = new JsonObject();
        request.addProperty("gameRoot", game.toString());
        request.addProperty("installedJar", mods.resolve("mintauth-test.jar").toString());
        request.addProperty("oldSha256", "invalid-synthetic-hash");
        request.addProperty("target", "forge-1.8.9");
        Path file = stage.resolve("request.json");
        Files.write(file, Json.GSON.toJson(request).getBytes(StandardCharsets.UTF_8));
        UpdateInstaller.main(new String[] {file.toString()});
        assertEquals(
                "failed",
                Json.string(UpdateInstaller.read(stage.resolve("result.json"), 1024), "status"));
        assertFalse(Files.exists(mods.resolve("mintauth-test.jar")));
    }
}
