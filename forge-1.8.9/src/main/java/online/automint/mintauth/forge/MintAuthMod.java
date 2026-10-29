// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.forge;

import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.*;
import net.minecraft.client.multiplayer.GuiConnecting;
import net.minecraft.client.multiplayer.ServerData;
import net.minecraft.launchwrapper.Launch;
import net.minecraft.util.ChatComponentText;
import net.minecraftforge.client.event.GuiOpenEvent;
import net.minecraftforge.client.event.GuiScreenEvent;
import net.minecraftforge.common.MinecraftForge;
import net.minecraftforge.fml.common.FMLCommonHandler;
import net.minecraftforge.fml.common.Mod;
import net.minecraftforge.fml.common.event.FMLInitializationEvent;
import net.minecraftforge.fml.common.eventhandler.SubscribeEvent;
import net.minecraftforge.fml.common.gameevent.TickEvent;
import net.minecraftforge.fml.common.network.FMLNetworkEvent;

import online.automint.mintauth.core.MintAuthRuntime;

import java.nio.file.Paths;

@Mod(
        modid = "mintauth",
        name = "MintAuth",
        version = "1.0.0",
        acceptedMinecraftVersions = "[1.8.9]",
        clientSideOnly = true)
public final class MintAuthMod {
    private static volatile MintAuthRuntime runtime;
    private int smokeStage, smokeTicks;
    private final java.util.Map<GuiScreen, java.util.List<GuiButton>> titleButtons =
            new java.util.WeakHashMap<>();

    public static MintAuthRuntime runtime() {
        return runtime;
    }

    @Mod.EventHandler
    public void initialize(FMLInitializationEvent event) {
        MinecraftForge.EVENT_BUS.register(this);
        FMLCommonHandler.instance().bus().register(this);
    }

    @SubscribeEvent
    public void tick(TickEvent.ClientTickEvent event) {
        if (event.phase != TickEvent.Phase.END) return;
        if (runtime == null) {
            org.apache.logging.log4j.LogManager.getLogger("MintAuth")
                    .info("[MintAuth] step=CLIENT_BOOTSTRAP result=STARTED target=forge-1.8.9");
            try {
                Minecraft mc = Minecraft.getMinecraft();
                String test = System.getProperty("mintauth.testVaultRoot");
                runtime =
                        Boolean.TRUE.equals(Launch.blackboard.get("fml.deobfuscatedEnvironment"))
                                        && test != null
                                ? new MintAuthRuntime(new ForgeGameBridge(mc), Paths.get(test))
                                : new MintAuthRuntime(new ForgeGameBridge(mc));
                java.io.File source =
                        net.minecraftforge.fml.common.Loader.instance()
                                .getIndexedModList()
                                .get("mintauth")
                                .getSource();
                if (source != null)
                    runtime.configureUpdates("forge-1.8.9", mc.mcDataDir.toPath(), source.toPath());
                Runtime.getRuntime()
                        .addShutdownHook(new Thread(() -> runtime.close(), "MintAuth shutdown"));
            } catch (Exception | LinkageError e) {
                org.apache.logging.log4j.LogManager.getLogger("MintAuth")
                        .warn("[MintAuth] step=CLIENT_BOOTSTRAP result=FAILED target=forge-1.8.9");
                MintAuthRuntime.logBootstrapFailure(
                        e,
                        line ->
                                org.apache.logging.log4j.LogManager.getLogger("MintAuth")
                                        .warn(line));
                throw new IllegalStateException(
                        "MintAuth secure storage could not initialize. See sanitized MintAuth trace"
                            + " logs.");
            }
        }
        runtime.tick();
        if (Boolean.TRUE.equals(Launch.blackboard.get("fml.deobfuscatedEnvironment"))
                && Boolean.getBoolean("mintauth.smoke")
                && System.getProperty("mintauth.testVaultRoot") != null) {
            Minecraft client = Minecraft.getMinecraft();
            if (++smokeTicks > 2400)
                throw new IllegalStateException("MintAuth development smoke timed out");
            if (smokeStage == 0 && client.currentScreen instanceof GuiMainMenu) {
                client.displayGuiScreen(new MintAuthGui(client.currentScreen));
                smokeStage = 1;
            } else if (smokeStage == 1 && client.currentScreen instanceof MintAuthGui) {
                System.out.println(
                        "MINTAUTH_DEVELOPMENT_SMOKE_PASSED: legacy session bridge and account"
                                + " screen initialized; no online compatibility claim");
                smokeStage = 2;
                client.shutdown();
            }
        }
    }

    private boolean menu(GuiScreen screen) {
        return screen instanceof GuiMainMenu
                || screen instanceof GuiOptions
                || screen instanceof GuiMultiplayer
                || screen instanceof GuiSelectWorld;
    }

    static final class OpenButton extends GuiButton {
        OpenButton(int x, int y, int width, int height) {
            super(987231, x, y, width, height, "MintAuth");
        }
    }

    @SubscribeEvent
    public void init(GuiScreenEvent.InitGuiEvent.Post event) {
        if (!menu(event.gui)) return;
        boolean title = event.gui instanceof GuiMainMenu;
        int actionWidth = title ? 104 : 72, actionHeight = title ? 20 : 16;
        int x = event.gui.width - actionWidth - 8;
        int y = event.gui instanceof GuiSelectWorld || event.gui instanceof GuiMultiplayer ? 16 : 8;
        event.buttonList.add(new OpenButton(x, y, actionWidth, actionHeight));
        if (event.gui instanceof GuiMainMenu) titleButtons.put(event.gui, event.buttonList);
        if (event.gui instanceof GuiMainMenu && runtime != null && runtime.activeId() != null)
            for (GuiButton button : event.buttonList) if (button.id == 14) button.enabled = false;
    }

    @SubscribeEvent
    public void action(GuiScreenEvent.ActionPerformedEvent.Pre event) {
        if (event.button instanceof OpenButton) {
            event.setCanceled(true);
            Minecraft.getMinecraft().displayGuiScreen(new MintAuthGui(event.gui));
        }
        if (runtime != null
                && runtime.activeId() != null
                && event.gui instanceof GuiMainMenu
                && event.button.id == 14) event.setCanceled(true);
    }

    @SubscribeEvent
    public void background(GuiScreenEvent.BackgroundDrawnEvent event) {
        if (runtime != null && runtime.theme() && menu(event.gui)) {
            Gui.drawRect(0, 0, event.gui.width, event.gui.height, 0x50132a18);
            Gui.drawRect(0, 0, event.gui.width, 2, 0xffa6ed83);
        }
    }

    @SubscribeEvent
    public void drawTitle(GuiScreenEvent.DrawScreenEvent.Pre event) {
        if (runtime != null
                && runtime.theme()
                && event.gui instanceof GuiMainMenu
                && titleButtons.containsKey(event.gui)
                && ForgeTitleTheme.render(
                        event.gui,
                        titleButtons.get(event.gui),
                        event.mouseX,
                        event.mouseY,
                        event.renderPartialTicks)) event.setCanceled(true);
    }

    @SubscribeEvent
    public void draw(GuiScreenEvent.DrawScreenEvent.Post event) {
        if (runtime != null
                && runtime.activeIgn() != null
                && menu(event.gui)
                && !(event.gui instanceof GuiMainMenu && runtime.theme()))
            Minecraft.getMinecraft()
                    .fontRendererObj
                    .drawStringWithShadow("MintAuth: " + runtime.activeIgn(), 8, 8, 0xffa6ed83);
    }

    @SubscribeEvent
    public void open(GuiOpenEvent event) {
        if (runtime == null) return;
        if (event.gui instanceof GuiConnecting) {
            if (!runtime.allowJoin()) {
                event.gui = new MintAuthGui(Minecraft.getMinecraft().currentScreen);
                return;
            }
            ServerData server = Minecraft.getMinecraft().getCurrentServerData();
            if (server != null) runtime.rememberDestination(server.serverIP);
        }
    }

    @SubscribeEvent
    public void connected(FMLNetworkEvent.ClientConnectedToServerEvent event) {
        if (runtime != null && !runtime.allowJoin()) {
            event.manager.closeChannel(
                    new ChatComponentText("MintAuth authorization needs checking"));
            Minecraft.getMinecraft()
                    .addScheduledTask(
                            () ->
                                    Minecraft.getMinecraft()
                                            .displayGuiScreen(new MintAuthGui(new GuiMainMenu())));
        }
    }
}
