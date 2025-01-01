package sk.janobono.simple.common.component;

import org.springframework.stereotype.Component;

import java.text.Normalizer;
import java.util.Optional;

@Component
public class ScDf {

    public String toStripAndLowerCase(final String text) {
        return Optional.ofNullable(text)
                .map(String::strip)
                .map(String::toLowerCase)
                .orElse(text);
    }

    public String toDf(final String text) {
        return Optional.ofNullable(text)
                .filter(s -> !s.isBlank())
                .map(s -> {
                    final StringBuilder ret = new StringBuilder();
                    final char[] cha = s.toCharArray();
                    for (final char aCha : cha) {
                        final byte[] ba = Normalizer.normalize(String.valueOf(aCha), Normalizer.Form.NFD).getBytes();
                        if (ba[0] >= 41 && ba[0] < 123) {
                            ret.append((char) ba[0]);
                        } else {
                            ret.append(aCha);
                        }
                    }
                    return ret.toString();
                })
                .orElse(null);
    }

    public String toScDf(final String text) {
        return Optional.ofNullable(text)
                .filter(s -> !s.isBlank())
                .map(this::toDf)
                .map(this::toStripAndLowerCase)
                .orElse(null);
    }
}
