package sk.janobono.simple.common.component;

import io.quarkus.elytron.security.common.BcryptUtil;
import jakarta.enterprise.context.ApplicationScoped;
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.util.Optional;
import java.util.Random;
import javax.imageio.ImageIO;
import org.apache.commons.lang3.RandomStringUtils;
import sk.janobono.simple.common.config.CommonConfigProperties;
import sk.janobono.simple.common.exception.SimpleAuthServiceException;

@ApplicationScoped
public class CaptchaUtil {

    private final int captchaLength;

    public CaptchaUtil(final CommonConfigProperties commonConfigProperties) {
        this.captchaLength = commonConfigProperties.captchaLength();
    }

    public String generateText() {
        return RandomStringUtils.secure().nextAlphanumeric(captchaLength);
    }

    public byte[] generateImage(final String text) {
        if (Optional.ofNullable(text).filter(s -> !s.isBlank()).isEmpty()) {
            return null;
        }

        final int w = 180;
        final int h = 40;
        final BufferedImage image = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        final Graphics2D g = image.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_FRACTIONALMETRICS, RenderingHints.VALUE_FRACTIONALMETRICS_ON);
        g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

        g.setColor(Color.white);
        g.fillRect(0, 0, w, h);
        g.setFont(new Font("Serif", Font.PLAIN, 26));
        g.setColor(Color.blue);
        final int start = 10;
        final byte[] bytes = text.getBytes();

        final Random random = new Random();
        for (int i = 0; i < bytes.length; i++) {
            g.setColor(new Color(random.nextInt(255), random.nextInt(255), random.nextInt(255)));
            g.drawString(new String(new byte[]{bytes[i]}), start + (i * 20), (int) (Math.random() * 20 + 20));
        }
        g.setColor(Color.white);
        for (int i = 0; i < 8; i++) {
            g.drawOval((int) (Math.random() * 160), (int) (Math.random() * 10), 30, 30);
        }
        g.dispose();
        final ByteArrayOutputStream bout = new ByteArrayOutputStream();
        try {
            ImageIO.write(image, "png", bout);
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
        return bout.toByteArray();
    }

    public String generateToken(final String text) {
        return Optional.ofNullable(text)
            .filter(s -> !s.isBlank())
            .map(BcryptUtil::bcryptHash)
            .orElse(null);
    }

    public boolean isTokenValid(final String text, final String token) {
        if (Optional.ofNullable(text).filter(s -> !s.isBlank()).isEmpty()) {
            return false;
        }

        if (Optional.ofNullable(token).filter(s -> !s.isBlank()).isEmpty()) {
            return false;
        }

        return BcryptUtil.matches(text, token);
    }

    public void checkTokenValid(final String text, final String token) {
        if (!isTokenValid(text, token)) {
            throw SimpleAuthServiceException.INVALID_CAPTCHA.exception("Invalid captcha.");
        }
    }
}
