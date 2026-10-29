// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.fabric;

import net.fabricmc.fabric.api.client.screen.v1.Screens;
import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.client.renderer.RenderPipelines;
import net.minecraft.network.chat.contents.TranslatableContents;
import net.minecraft.resources.Identifier;

import online.automint.mintauth.core.TitleTheme;

import java.util.*;

public final class FabricTitleTheme {
    private static final net.minecraft.client.gui.components.LogoRenderer MINECRAFT_LOGO =
            new net.minecraft.client.gui.components.LogoRenderer(false);
    private static final Identifier LOGO =
            Identifier.fromNamespaceAndPath("mintauth", "textures/gui/mintauth-signature.png");

    private static final ThreadLocal<Boolean> suppressPaint = new ThreadLocal<>();

    public static boolean suppressNativeTitlePaint() {
        return Boolean.TRUE.equals(suppressPaint.get());
    }

    private FabricTitleTheme() {}

    public static boolean render(
            Screen screen, GuiGraphics g, int mouseX, int mouseY, float delta) {
        if (MintAuthClient.runtime() == null || !MintAuthClient.runtime().theme()) return false;
        Minecraft client = Minecraft.getInstance();
        List<TitleTheme.Button> buttons = new ArrayList<>();
        for (var widget : Screens.getButtons(screen))
            buttons.add(
                    new TitleTheme.Button() {
                        public String key() {
                            if (widget.getClass().getSimpleName().equals("FriendsButton"))
                                return "friends";
                            if (widget.getMessage().getString().equals("MintAuth"))
                                return "mintauth";
                            if (widget.getMessage().getContents()
                                    instanceof TranslatableContents content)
                                switch (content.getKey()) {
                                    case "menu.singleplayer":
                                        return "singleplayer";
                                    case "menu.multiplayer":
                                        return "multiplayer";
                                    case "menu.online":
                                        return "realms";
                                    case "menu.options":
                                        return "options";
                                    case "menu.quit":
                                        return "quit";
                                    case "options.language":
                                        return "language";
                                    case "options.accessibility":
                                    case "accessibility.onboarding.accessibility.button":
                                    case "options.accessibility.title":
                                        return "accessibility";
                                    case "narrator.button.accessibility":
                                        return "accessibility";
                                    case "title.credits":
                                        return "credits";
                                    case "modmenu.title":
                                        return "mods";
                                }
                            if (widget.getMessage().getString().startsWith("Copyright Mojang"))
                                return "credits";
                            return "extra";
                        }

                        public String label() {
                            return widget.getMessage().getString();
                        }

                        public boolean enabled() {
                            return widget.active;
                        }

                        public boolean visible() {
                            return widget.visible;
                        }

                        public boolean focused() {
                            return widget.isFocused();
                        }

                        public void bounds(int x, int y, int width, int height) {
                            widget.setX(x);
                            widget.setY(y);
                            widget.setWidth(width);
                            widget.setHeight(height);
                        }

                        public void original() {
                            String key = key();
                            boolean themed =
                                    !key.equals("extra")
                                            && !key.equals("language")
                                            && !key.equals("accessibility")
                                            && !key.equals("credits")
                                            && !key.equals("friends");
                            if (themed) suppressPaint.set(Boolean.TRUE);
                            try {
                                widget.render(g, mouseX, mouseY, delta);
                            } finally {
                                if (themed) suppressPaint.remove();
                            }
                        }
                    });
        TitleTheme.Canvas canvas =
                new TitleTheme.Canvas() {
                    public boolean panorama() {
                        ((online.automint.mintauth.fabric.mixin.ScreenPanoramaAccess) screen)
                                .mintauth$panorama(g, delta);
                        return true;
                    }

                    public void fill(int x, int y, int right, int bottom, int color) {
                        g.fill(x, y, right, bottom, color);
                    }

                    public int textWidth(String value) {
                        return client.font.width(value);
                    }

                    public void text(String value, int x, int y, int color) {
                        g.drawString(client.font, value, x, y, color, false);
                    }

                    public void minecraft(int screenWidth, int y) {
                        MINECRAFT_LOGO.renderLogo(g, screenWidth, 1.0F, y);
                    }

                    public void brand(int x, int y, int width, int height) {
                        g.blit(
                                RenderPipelines.GUI_TEXTURED,
                                LOGO,
                                x,
                                y,
                                0F,
                                0F,
                                width,
                                height,
                                960,
                                160,
                                960,
                                160);
                    }
                };
        return TitleTheme.render(
                canvas,
                buttons,
                screen.width,
                screen.height,
                mouseX,
                mouseY,
                MintAuthClient.runtime().accountMenuLabel(),
                "Minecraft 1.21.11 / Fabric");
    }
}
