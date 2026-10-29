// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import java.util.*;

public final class TitleTheme {
    private TitleTheme() {}

    public interface Canvas {
        boolean panorama();

        void fill(int x1, int y1, int x2, int y2, int color);

        void text(String value, int x, int y, int color);

        int textWidth(String value);

        void brand(int x, int y, int width, int height);

        void minecraft(int screenWidth, int y);
    }

    public interface Button {
        String key();

        String label();

        boolean enabled();

        boolean focused();

        boolean visible();

        void bounds(int x, int y, int width, int height);

        void original();
    }

    private static final class Box {
        final int x, y, w, h;

        Box(int x, int y, int w, int h) {
            this.x = x;
            this.y = y;
            this.w = w;
            this.h = h;
        }
    }

    public static boolean render(
            Canvas g,
            List<Button> buttons,
            int width,
            int height,
            int mouseX,
            int mouseY,
            String accountLabel,
            String version) {
        if (width < 320 || height < 240) return false;
        int span = Math.min(230, width - 48), left = (width - span) / 2;
        int start = Math.max(94, height / 4 + 34), half = (span - 6) / 2;
        Map<Button, Box> boxes = new IdentityHashMap<>();
        boolean multiplayer = false, singleplayer = false, mods = false;
        for (Button button : buttons) {
            if (button.key().equals("mods")) mods = true;
        }
        int extras = 0;
        for (Button button : buttons) {
            String key = button.key();
            Box box;
            switch (key) {
                case "multiplayer":
                    box = new Box(left, start, span, 20);
                    multiplayer = true;
                    break;
                case "singleplayer":
                    box = new Box(left, start + 24, span, 20);
                    singleplayer = true;
                    break;
                case "mintauth":
                    box = new Box(left, start + 48, span, 20);
                    break;
                case "mods":
                    box = new Box(left, start + 72, half, 20);
                    break;
                case "realms":
                    box =
                            new Box(
                                    mods ? left + half + 6 : left,
                                    start + 72,
                                    mods ? span - half - 6 : span,
                                    20);
                    break;
                case "options":
                    box = new Box(left, start + 96, half, 20);
                    break;
                case "quit":
                    box = new Box(left + half + 6, start + 96, span - half - 6, 20);
                    break;
                case "language":
                    box = new Box(12, 5, 20, 20);
                    break;
                case "accessibility":
                    box = new Box(36, 5, 20, 20);
                    break;
                case "friends":
                    box = new Box(60, 5, 20, 20);
                    break;
                case "credits":
                    box =
                            new Box(
                                    Math.max(12, width - g.textWidth(button.label()) - 12),
                                    height - 13,
                                    g.textWidth(button.label()),
                                    10);
                    break;
                default:
                    int rail = left - 24;
                    if (rail < 60 || start + extras * 26 + 22 > height - 50) return false;
                    box = new Box(12, start + extras++ * 26, rail, 22);
                    break;
            }
            boxes.put(button, box);
        }
        if (!multiplayer || !singleplayer) return false;
        if (!g.panorama()) return false;
        int brandWidth = 126, brandHeight = 21;
        g.brand((width - brandWidth) / 2 + 4, 5, brandWidth, brandHeight);
        g.minecraft(width, 30);
        for (Button button : buttons) {
            if (!button.visible()) continue;
            Box box = boxes.get(button);
            button.bounds(box.x, box.y, box.w, box.h);
            button.original();
            String key = button.key();
            if (key.equals("language")
                    || key.equals("accessibility")
                    || key.equals("credits")
                    || key.equals("friends")
                    || key.equals("extra")) continue;
            boolean hover =
                    button.enabled()
                            && (button.focused()
                                    || mouseX >= box.x
                                            && mouseX < box.x + box.w
                                            && mouseY >= box.y
                                            && mouseY < box.y + box.h);
            boolean primary = key.equals("multiplayer"), account = key.equals("mintauth");
            int border = hover ? 0xff09ed89 : account ? 0xff3c7659 : 0xff31483b;
            g.fill(box.x, box.y + 1, box.x + box.w, box.y + box.h + 1, 0x66000000);
            g.fill(box.x, box.y, box.x + box.w, box.y + box.h, border);
            g.fill(
                    box.x + 1,
                    box.y + 1,
                    box.x + box.w - 1,
                    box.y + box.h - 1,
                    !button.enabled()
                            ? 0xff15211b
                            : primary
                                    ? (hover ? 0xff65ffad : 0xff09ed89)
                                    : hover ? 0xff213d2e : 0xff16281e);
            if (account) g.fill(box.x + 1, box.y + 1, box.x + 3, box.y + box.h - 1, 0xff09ed89);
            String label = account ? accountLabel : button.label();
            while (g.textWidth(label) > box.w - 20 && label.length() > 3)
                label = label.substring(0, label.length() - 4) + "...";
            int color =
                    !button.enabled()
                            ? 0xff667c6c
                            : primary ? 0xff082719 : account ? 0xffa7ffcc : 0xffe0efe5;
            g.text(label, box.x + (box.w - g.textWidth(label)) / 2, box.y + (box.h - 8) / 2, color);
            if (hover) g.text(">", box.x + 7, box.y + (box.h - 8) / 2, color);
        }
        g.text(version, 12, height - 24, 0xffc4d8c9);
        boolean credits = false;
        for (Button button : buttons) if (button.key().equals("credits")) credits = true;
        if (!credits) {
            String legal = "Copyright Mojang AB";
            g.text(legal, width - g.textWidth(legal) - 12, height - 13, 0xffaac5b3);
        }
        return true;
    }
}
