// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

public final class MintLoadingAnimation {
    @FunctionalInterface
    public interface Canvas {
        void fill(int left, int top, int right, int bottom, int color);
    }

    private static final String[] MARK = {
        "1000001", "1100011", "1010101", "1001001", "1000001", "1000001", "1000001"
    };

    private MintLoadingAnimation() {}

    public static void draw(
            Canvas canvas,
            int centerX,
            int top,
            int width,
            int height,
            long elapsedMillis,
            boolean mint) {
        if (width < 24 || height < 12) return;
        double scale = Math.min(1.25, Math.min(width / 156.0, height / 88.0));
        double originX = centerX - 78 * scale;
        double originY = top + (height - 88 * scale) / 2;
        double phase = (Math.max(0, elapsedMillis) % 3200) / 3200.0;
        double angle = phase * Math.PI * 2;
        int accent = mint ? 0xff00e788 : 0xffb4d7c5;
        int light = mint ? 0xffa6ffc9 : 0xffdeede4;
        int face = mint ? 0xff139966 : 0xff547367;
        int side = mint ? 0xff0b5d43 : 0xff344d42;

        rect(canvas, originX, originY, scale, 53, 65, 103, 67, 0xff0c241b);
        rect(canvas, originX, originY, scale, 61, 63, 95, 69, 0xff103022);
        for (int x = 9; x < 156; x += 9) {
            if (x > 48 && x < 108) continue;
            rect(canvas, originX, originY, scale, x, 43, x + 2, 44, 0xff254b39);
        }

        for (int i = 0; i < 4; i++) {
            double travel = (phase + i * .25) % 1;
            int x = (int) Math.round(8 + travel * 140);
            int y = 37 + (int) Math.round(Math.sin(travel * Math.PI * 2) * 8);
            if (x < 48 || x > 108)
                cube(canvas, originX, originY, scale, x, y, 4, 2, 5, accent, face, side, false);
        }

        int orbitX = 78 + (int) Math.round(Math.cos(angle) * 40);
        int orbitY = 38 + (int) Math.round(Math.sin(angle) * 16);
        if (Math.sin(angle) < 0)
            cube(
                    canvas, originX, originY, scale, orbitX, orbitY, 3, 2, 4, light, face, side,
                    false);

        int bob = (int) Math.round(Math.sin(angle) * 2);
        cube(canvas, originX, originY, scale, 78, 12 + bob, 20, 10, 26, accent, face, side, true);

        int glint = (int) Math.round(phase * 16);
        rect(
                canvas,
                originX,
                originY,
                scale,
                79 + glint,
                13 + bob + glint / 2,
                83 + glint,
                14 + bob + glint / 2,
                light);
        if (Math.sin(angle) >= 0)
            cube(
                    canvas, originX, originY, scale, orbitX, orbitY, 3, 2, 4, light, face, side,
                    false);

        rect(canvas, originX, originY, scale, 28, 79, 128, 81, 0xff234637);
        double sweep = .5 - .5 * Math.cos(angle);
        int runner = 28 + (int) Math.round(sweep * 80);
        rect(canvas, originX, originY, scale, runner, 79, runner + 20, 81, face);
        rect(canvas, originX, originY, scale, runner + 5, 79, runner + 15, 81, accent);
    }

    private static void cube(
            Canvas canvas,
            double ox,
            double oy,
            double scale,
            int cx,
            int y,
            int half,
            int depth,
            int height,
            int topColor,
            int leftColor,
            int rightColor,
            boolean mark) {
        for (int x = 0; x < half; x++) {
            int leftY = y + depth + x * depth / half;
            int rightY = y + depth * 2 - (x + 1) * depth / half;
            rect(
                    canvas,
                    ox,
                    oy,
                    scale,
                    cx - half + x,
                    leftY,
                    cx - half + x + 1,
                    leftY + height,
                    leftColor);
            rect(canvas, ox, oy, scale, cx + x, rightY, cx + x + 1, rightY + height, rightColor);
        }
        for (int row = 0; row < depth * 2; row++) {
            int radius = Math.min(row + 1, depth * 2 - row) * half / depth;
            rect(canvas, ox, oy, scale, cx - radius, y + row, cx + radius, y + row + 1, topColor);
        }
        if (mark) {
            for (int row = 0; row < MARK.length; row++) {
                for (int col = 0; col < MARK[row].length(); col++) {
                    if (MARK[row].charAt(col) != '1') continue;
                    int x = cx - half + 3 + col * 2;
                    int baseline = y + depth + (3 + col * 2) * depth / half + 5;
                    rect(
                            canvas,
                            ox,
                            oy,
                            scale,
                            x,
                            baseline + row * 2,
                            x + 2,
                            baseline + row * 2 + 2,
                            0xffd3ffe6);
                }
            }
        }
    }

    private static void rect(
            Canvas canvas,
            double ox,
            double oy,
            double scale,
            int left,
            int top,
            int right,
            int bottom,
            int color) {
        int x1 = (int) Math.round(ox + left * scale), x2 = (int) Math.round(ox + right * scale);
        int y1 = (int) Math.round(oy + top * scale), y2 = (int) Math.round(oy + bottom * scale);
        if (x2 > x1 && y2 > y1) canvas.fill(x1, y1, x2, y2, color);
    }
}
