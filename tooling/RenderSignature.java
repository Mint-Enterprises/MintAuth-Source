// Copyright (c) 2026 AutoMint. License: see LICENSE.
import java.awt.*;
import java.awt.font.GlyphVector;
import java.awt.image.BufferedImage;
import java.io.File;

import javax.imageio.ImageIO;

public final class RenderSignature {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("Expected project root");
        File root = new File(args[0]);
        BufferedImage mark = ImageIO.read(new File(root, "branding/mint-logo.png"));
        BufferedImage image = new BufferedImage(960, 160, BufferedImage.TYPE_INT_ARGB);
        Graphics2D graphics = image.createGraphics();
        graphics.setRenderingHint(
                RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        graphics.setRenderingHint(
                RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        graphics.setRenderingHint(
                RenderingHints.KEY_FRACTIONALMETRICS, RenderingHints.VALUE_FRACTIONALMETRICS_ON);
        graphics.setRenderingHint(
                RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BICUBIC);
        Font font = new Font("Arial", Font.BOLD, 114);
        if (!font.getFamily().equals("Arial"))
            throw new IllegalStateException("Arial authoring font unavailable");
        graphics.setFont(font);
        GlyphVector mint = font.createGlyphVector(graphics.getFontRenderContext(), "Mint");
        GlyphVector auth = font.createGlyphVector(graphics.getFontRenderContext(), "Auth");
        double mintWidth = mint.getLogicalBounds().getBounds2D().getWidth();
        double authWidth = auth.getLogicalBounds().getBounds2D().getWidth();
        double left = (960 - (128 + 96 + mintWidth + authWidth)) / 2;
        graphics.drawImage(mark, (int) Math.round(left), 16, 128, 128, null);
        graphics.setColor(new Color(0x284c3a));
        graphics.fillRect((int) Math.round(left + 128 + 43), 31, 3, 98);
        float x = (float) (left + 128 + 96), baseline = 120;
        Shape first = mint.getOutline(x, baseline);
        Shape second = auth.getOutline((float) (x + mintWidth), baseline);
        graphics.setStroke(new BasicStroke(4, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
        graphics.setColor(new Color(0x203d31));
        graphics.draw(first);
        graphics.draw(second);
        graphics.setColor(new Color(0xeffff5));
        graphics.fill(first);
        graphics.setColor(new Color(0x00ed89));
        graphics.fill(second);
        graphics.dispose();
        File output = new File(root, "branding/mintauth-signature.png");
        ImageIO.write(image, "png", output);
        System.out.println(
                "Mint signature: 960 x 160 transparent texture, official mark preserved.");
    }
}
