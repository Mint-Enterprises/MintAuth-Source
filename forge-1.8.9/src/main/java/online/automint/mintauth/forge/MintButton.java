// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.forge;

import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.Gui;
import net.minecraft.client.gui.GuiButton;
import net.minecraft.client.renderer.GlStateManager;

import online.automint.mintauth.core.ActionButtonStyle;

public class MintButton extends GuiButton {
    private boolean tab, selected, primary, quiet, focused;

    public MintButton primary() {
        primary = true;
        return this;
    }

    public MintButton quiet() {
        quiet = true;
        return this;
    }

    public void keyboardFocused(boolean value) {
        focused = value;
    }

    public MintButton(int id, int x, int y, int width, int height, String label) {
        super(id, x, y, width, height, label);
    }

    public MintButton tab(boolean selected) {
        this.tab = true;
        this.selected = selected;
        return this;
    }

    public boolean needsTooltip(Minecraft client, int mouseX, int mouseY) {
        return visible
                && mouseX >= xPosition
                && mouseX < xPosition + width
                && mouseY >= yPosition
                && mouseY < yPosition + height
                && client.fontRendererObj.getStringWidth(displayString) > width - (tab ? 8 : 12);
    }

    @Override
    public void drawButton(Minecraft client, int mouseX, int mouseY) {
        if (!visible) return;
        hovered =
                mouseX >= xPosition
                        && mouseX < xPosition + width
                        && mouseY >= yPosition
                        && mouseY < yPosition + height;
        GlStateManager.disableDepth();
        if (primary || quiet) {
            boolean mint = MintAuthMod.runtime() == null || MintAuthMod.runtime().theme();
            int accent = mint ? 0xff09ed89 : 0xffdedede;
            boolean highlight = enabled && (hovered || focused);
            if (!quiet || focused) {
                Gui.drawRect(
                        xPosition,
                        yPosition,
                        xPosition + width,
                        yPosition + height,
                        highlight ? accent : mint ? 0xff3a5747 : 0xff606060);
                Gui.drawRect(
                        xPosition + 1,
                        yPosition + 1,
                        xPosition + width - 1,
                        yPosition + height - 1,
                        !enabled
                                ? 0xff18221b
                                : primary
                                        ? (highlight ? (mint ? 0xff65ffad : 0xfff4f4f4) : accent)
                                        : 0xff182e22);
            }
            String label =
                    client.fontRendererObj.trimStringToWidth(
                            displayString, Math.max(0, width - 12));
            int color =
                    !enabled ? 0xff879b8d : primary ? 0xff082719 : highlight ? accent : 0xffa6baae;
            client.fontRendererObj.drawString(
                    label,
                    xPosition + (width - client.fontRendererObj.getStringWidth(label)) / 2,
                    yPosition + (height - 8) / 2,
                    color);
            if (quiet && highlight)
                Gui.drawRect(
                        xPosition + (width - client.fontRendererObj.getStringWidth(label)) / 2,
                        yPosition + height - 3,
                        xPosition + (width + client.fontRendererObj.getStringWidth(label)) / 2,
                        yPosition + height - 2,
                        color);
            return;
        }
        ActionButtonStyle.draw(
                new ActionButtonStyle.Canvas() {
                    public void fill(int x, int y, int right, int bottom, int color) {
                        Gui.drawRect(x, y, right, bottom, color);
                    }

                    public int textWidth(String value) {
                        return client.fontRendererObj.getStringWidth(value);
                    }

                    public void text(String value, int x, int y, int color) {
                        client.fontRendererObj.drawString(value, x, y, color);
                    }
                },
                xPosition,
                yPosition,
                width,
                height,
                displayString,
                enabled,
                hovered || focused,
                tab,
                selected,
                MintAuthMod.runtime() == null || MintAuthMod.runtime().theme());
        mouseDragged(client, mouseX, mouseY);
    }
}
