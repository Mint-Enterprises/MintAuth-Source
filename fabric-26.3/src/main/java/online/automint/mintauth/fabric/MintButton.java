// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.fabric;

import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.GuiGraphicsExtractor;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.Tooltip;
import net.minecraft.network.chat.Component;

import online.automint.mintauth.core.ActionButtonStyle;

public final class MintButton extends Button {
    private boolean tab, selected, primary, quiet;

    public MintButton primary() {
        primary = true;
        return this;
    }

    public MintButton quiet() {
        quiet = true;
        return this;
    }

    public MintButton(String label, int x, int y, int width, int height, Runnable action) {
        super(x, y, width, height, Component.literal(label), b -> action.run(), DEFAULT_NARRATION);
        if (Minecraft.getInstance().font.width(label) > width - 12)
            setTooltip(Tooltip.create(Component.literal(label)));
    }

    public MintButton tab(boolean selected) {
        this.tab = true;
        this.selected = selected;
        return this;
    }

    @Override
    protected void extractContents(
            GuiGraphicsExtractor graphics, int mouseX, int mouseY, float delta) {
        Minecraft client = Minecraft.getInstance();
        if (primary || quiet) {
            boolean mint = MintAuthClient.runtime() == null || MintAuthClient.runtime().theme();
            int accent = mint ? 0xff09ed89 : 0xffdedede;
            boolean highlight = active && isHoveredOrFocused();
            int x = getX(), y = getY(), w = getWidth(), h = getHeight();
            if (!quiet || isFocused()) {
                graphics.fill(
                        x, y, x + w, y + h, highlight ? accent : mint ? 0xff3a5747 : 0xff606060);
                graphics.fill(
                        x + 1,
                        y + 1,
                        x + w - 1,
                        y + h - 1,
                        !active
                                ? 0xff18221b
                                : primary
                                        ? (highlight ? (mint ? 0xff65ffad : 0xfff4f4f4) : accent)
                                        : 0xff182e22);
            }
            String label =
                    client.font.plainSubstrByWidth(getMessage().getString(), Math.max(0, w - 12));
            int color =
                    !active ? 0xff879b8d : primary ? 0xff082719 : highlight ? accent : 0xffa6baae;
            graphics.text(
                    client.font,
                    label,
                    x + (w - client.font.width(label)) / 2,
                    y + (h - 8) / 2,
                    color,
                    false);
            if (quiet && highlight)
                graphics.fill(
                        x + (w - client.font.width(label)) / 2,
                        y + h - 3,
                        x + (w + client.font.width(label)) / 2,
                        y + h - 2,
                        color);
            return;
        }
        ActionButtonStyle.draw(
                new ActionButtonStyle.Canvas() {
                    public void fill(int x, int y, int right, int bottom, int color) {
                        graphics.fill(x, y, right, bottom, color);
                    }

                    public int textWidth(String value) {
                        return client.font.width(value);
                    }

                    public void text(String value, int x, int y, int color) {
                        graphics.text(client.font, value, x, y, color, false);
                    }
                },
                getX(),
                getY(),
                getWidth(),
                getHeight(),
                getMessage().getString(),
                active,
                isHoveredOrFocused(),
                tab,
                selected,
                MintAuthClient.runtime() == null || MintAuthClient.runtime().theme());
    }
}
