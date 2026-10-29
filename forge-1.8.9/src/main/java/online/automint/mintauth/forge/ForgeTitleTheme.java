// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.forge;

import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.*;
import net.minecraft.client.renderer.GlStateManager;
import net.minecraft.util.ResourceLocation;

import online.automint.mintauth.core.TitleTheme;

import java.util.*;

public final class ForgeTitleTheme {
    private static ResourceLocation logo;
    private static final ResourceLocation MINECRAFT_LOGO =
            new ResourceLocation("textures/gui/title/minecraft.png");

    private static java.lang.reflect.Method panorama;

    private ForgeTitleTheme() {}

    private static boolean panorama(GuiScreen screen, int mouseX, int mouseY, float delta) {
        try {
            if (panorama == null) {
                for (String name : new String[] {"renderSkybox", "func_73971_c"}) {
                    try {
                        panorama =
                                GuiMainMenu.class.getDeclaredMethod(
                                        name, int.class, int.class, float.class);
                        break;
                    } catch (NoSuchMethodException ignored) {
                    }
                }
                if (panorama == null) return false;
                panorama.setAccessible(true);
            }
            GlStateManager.disableAlpha();
            panorama.invoke(screen, mouseX, mouseY, delta);
            return true;
        } catch (ReflectiveOperationException ignored) {
            return false;
        } finally {
            GlStateManager.enableAlpha();
        }
    }

    public static boolean render(
            GuiScreen screen, List<GuiButton> widgets, int mouseX, int mouseY, float delta) {
        Minecraft client = Minecraft.getMinecraft();
        List<TitleTheme.Button> buttons = new ArrayList<>();
        for (GuiButton widget : widgets)
            buttons.add(
                    new TitleTheme.Button() {
                        public String key() {
                            switch (widget.id) {
                                case 1:
                                    return "singleplayer";
                                case 2:
                                    return "multiplayer";
                                case 14:
                                    return "realms";
                                case 6:
                                    return "mods";
                                case 0:
                                    return "options";
                                case 4:
                                    return "quit";
                                case 5:
                                    return "language";
                                case 987231:
                                    return "mintauth";
                                default:
                                    return "extra";
                            }
                        }

                        public String label() {
                            return widget.displayString;
                        }

                        public boolean enabled() {
                            return widget.enabled;
                        }

                        public boolean visible() {
                            return widget.visible;
                        }

                        public boolean focused() {
                            return false;
                        }

                        public void bounds(int x, int y, int width, int height) {
                            widget.xPosition = x;
                            widget.yPosition = y;
                            widget.width = width;
                            widget.height = height;
                        }

                        public void original() {
                            if (key().equals("extra") || key().equals("language"))
                                widget.drawButton(client, mouseX, mouseY);
                            GlStateManager.disableDepth();
                        }
                    });
        TitleTheme.Canvas canvas =
                new TitleTheme.Canvas() {
                    public boolean panorama() {
                        return ForgeTitleTheme.panorama(screen, mouseX, mouseY, delta);
                    }

                    public void fill(int x, int y, int right, int bottom, int color) {
                        GlStateManager.disableDepth();
                        Gui.drawRect(x, y, right, bottom, color);
                    }

                    public int textWidth(String value) {
                        return client.fontRendererObj.getStringWidth(value);
                    }

                    public void text(String value, int x, int y, int color) {
                        if (color == 0xff082719)
                            client.fontRendererObj.drawString(value, x, y, color);
                        else client.fontRendererObj.drawStringWithShadow(value, x, y, color);
                    }

                    public void minecraft(int screenWidth, int y) {
                        GlStateManager.color(1, 1, 1, 1);
                        GlStateManager.enableBlend();
                        GlStateManager.tryBlendFuncSeparate(770, 771, 1, 0);
                        client.getTextureManager().bindTexture(MINECRAFT_LOGO);
                        int x = (screenWidth - 310) / 2;
                        Gui.drawModalRectWithCustomSizedTexture(x, y, 0, 0, 155, 44, 256, 256);
                        Gui.drawModalRectWithCustomSizedTexture(
                                x + 155, y, 0, 45, 155, 44, 256, 256);
                        GlStateManager.disableBlend();
                    }

                    public void brand(int x, int y, int width, int height) {
                        GlStateManager.color(1, 1, 1, 1);
                        if (logo == null) {
                            try (java.io.InputStream input =
                                    ForgeTitleTheme.class.getResourceAsStream(
                                            "/assets/mintauth/textures/gui/mintauth-signature.png")) {
                                if (input == null)
                                    throw new java.io.IOException("Missing bundled logo");
                                net.minecraft.client.renderer.texture.DynamicTexture texture =
                                        new net.minecraft.client.renderer.texture.DynamicTexture(
                                                javax.imageio.ImageIO.read(input));
                                texture.setBlurMipmap(true, false);
                                logo =
                                        client.getTextureManager()
                                                .getDynamicTextureLocation(
                                                        "mintauth_signature", texture);
                            } catch (java.io.IOException error) {
                                return;
                            }
                        }
                        client.getTextureManager().bindTexture(logo);
                        GlStateManager.enableBlend();
                        GlStateManager.tryBlendFuncSeparate(770, 771, 1, 0);
                        Gui.drawScaledCustomSizeModalRect(
                                x, y, 0, 0, 960, 160, width, height, 960, 160);
                        GlStateManager.disableBlend();
                    }
                };
        return TitleTheme.render(
                canvas,
                buttons,
                screen.width,
                screen.height,
                mouseX,
                mouseY,
                MintAuthMod.runtime().accountMenuLabel(),
                "Minecraft 1.8.9 / Forge");
    }
}
