package sk.janobono.simple.common.component;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import sk.janobono.simple.common.config.VerificationConfigProperties;

class VerificationTokenTest {

    @Test
    void generateToken_whenNullInput_thenException() {
        // Given
        final VerificationConfigProperties verificationConfigProperties = new VerificationConfigProperties() {
            @Override
            public String issuer() {
                return "test";
            }
        };
        final VerificationToken verificationToken = new VerificationToken(verificationConfigProperties);

        // Then
        Assertions.assertThrows(
            RuntimeException.class,
            () -> verificationToken.generateToken(null, null, null)
        );
        Assertions.assertThrows(
            RuntimeException.class,
            () -> verificationToken.generateToken(Map.of(), null, null)
        );
        Assertions.assertThrows(
            RuntimeException.class,
            () -> verificationToken.generateToken(Map.of(), 0L, null)
        );
    }

    @Test
    void generateToken_whenValidInput_thenResult() {
        // Given
        final VerificationConfigProperties verificationConfigProperties = new VerificationConfigProperties() {
            @Override
            public String issuer() {
                return "test";
            }
        };
        final VerificationToken verificationToken = new VerificationToken(verificationConfigProperties);

        // When
        final String token = verificationToken.generateToken(Map.of(), 0L, 0L);

        // Then
        assertThat(token).isNotBlank();
    }

    @Test
    void parseToken_whenExpiredToken_thenResult() {
        // Given
        final VerificationConfigProperties verificationConfigProperties = new VerificationConfigProperties() {
            @Override
            public String issuer() {
                return "test";
            }
        };
        final VerificationToken verificationToken = new VerificationToken(verificationConfigProperties);
        final String token = verificationToken.generateToken(Map.of(), 0L, 0L);

        // Then
        Assertions.assertThrows(
            RuntimeException.class,
            () -> verificationToken.parseToken(token)
        );
    }

    @Test
    void parseToken_whenValidToken_thenResult() {
        // Given
        final VerificationConfigProperties verificationConfigProperties = new VerificationConfigProperties() {
            @Override
            public String issuer() {
                return "test";
            }
        };
        final VerificationToken verificationToken = new VerificationToken(verificationConfigProperties);

        final long issuedAt = System.currentTimeMillis();
        final String token = verificationToken.generateToken(Map.of("1", "TEST"), issuedAt, issuedAt + TimeUnit.MINUTES.toMillis(1));

        // Then
        final Map<String, String> content = verificationToken.parseToken(token);

        // Then
        assertThat(content).isNotNull();
        assertThat(content.containsKey("1")).isTrue();
        assertThat(content.get("1")).isEqualTo("TEST");
    }
}
