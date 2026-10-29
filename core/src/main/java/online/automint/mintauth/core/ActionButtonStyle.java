// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

public final class ActionButtonStyle {
    private ActionButtonStyle() {}

    public interface Canvas {
        void fill(int x1, int y1, int x2, int y2, int color);

        void text(String value, int x, int y, int color);

        int textWidth(String value);
    }

    public static boolean primary(String label) {
        return label.equals("Save SSID")
                || label.equals("Play")
                || label.equals("Link AutoMint")
                || label.equals("Start linking")
                || label.equals("Unlock existing vault");
    }

    public static boolean destructive(String label) {
        return label.equals("Delete cloud")
                || label.equals("Unlink & clear this device")
                || label.equals("Clear local credentials")
                || label.equals("Reset cleared vault");
    }

    public static void draw(
            Canvas g,
            int x,
            int y,
            int width,
            int height,
            String label,
            boolean enabled,
            boolean highlighted,
            boolean tab,
            boolean selected,
            boolean mint) {
        highlighted &= enabled;
        boolean primary = !tab && primary(label), danger = !tab && destructive(label);
        int accent = mint ? 0xff09ed89 : 0xffdedede;
        int border =
                !enabled
                        ? (mint ? 0xff293d32 : 0xff383838)
                        : highlighted
                                ? accent
                                : selected
                                        ? accent
                                        : danger
                                                ? (mint ? 0xff97554c : 0xff777777)
                                                : (mint ? 0xff3a5747 : 0xff606060);
        int background =
                !enabled
                        ? (mint ? 0xff14221a : 0xff222222)
                        : primary
                                ? (highlighted ? (mint ? 0xff65ffad : 0xfff4f4f4) : accent)
                                : selected
                                        ? (mint ? 0xff224332 : 0xff424242)
                                        : highlighted
                                                ? (mint ? 0xff284b37 : 0xff505050)
                                                : (mint ? 0xff182e22 : 0xff303030);
        g.fill(x, y + 1, x + width, y + height + 1, 0x50000000);
        g.fill(x, y, x + width, y + height, border);
        g.fill(x + 1, y + 1, x + width - 1, y + height - 1, background);
        if (tab && selected) g.fill(x + 1, y + height - 3, x + width - 1, y + height - 1, accent);
        int color =
                !enabled
                        ? (mint ? 0xff879b8d : 0xff929292)
                        : primary
                                ? 0xff082719
                                : danger && mint
                                        ? 0xffffc3b8
                                        : selected && mint ? 0xffc4ffde : 0xffedf5ee;
        int available = Math.max(0, width - (tab ? 8 : 12));
        String caption = label;
        if (g.textWidth(caption) > available) {
            while (!caption.isEmpty() && g.textWidth(caption + "...") > available)
                caption = caption.substring(0, caption.length() - 1);
            caption = caption + "...";
        }
        g.text(caption, x + (width - g.textWidth(caption)) / 2, y + (height - 8) / 2, color);
    }
}
