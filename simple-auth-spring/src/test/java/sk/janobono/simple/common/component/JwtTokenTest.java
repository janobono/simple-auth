package sk.janobono.simple.common.component;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import sk.janobono.simple.api.model.Authority;
import sk.janobono.simple.common.config.JwtConfigProperties;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JwtTokenTest {

    @Test
    void generateToken_whenNullInput_thenException() {
        // Given
        final JwtConfigProperties jwtConfigProperties = new JwtConfigProperties("test", 1);
        final JwtToken jwtToken = new JwtToken(jwtConfigProperties);

        // Then
        Assertions.assertThrows(
                RuntimeException.class,
                () -> jwtToken.generateToken(null, null)
        );
        Assertions.assertThrows(
                RuntimeException.class,
                () -> jwtToken.generateToken(new JwtToken.JwtContent(null, null), null)
        );
        Assertions.assertThrows(
                RuntimeException.class,
                () -> jwtToken.generateToken(new JwtToken.JwtContent(1L, null), null)
        );
    }

    @Test
    void generateToken_whenValidInput_thenResult() {
        // Given
        final JwtConfigProperties jwtConfigProperties = new JwtConfigProperties("test", 1);
        final JwtToken jwtToken = new JwtToken(jwtConfigProperties);

        // When
        final String token01 = jwtToken.generateToken(new JwtToken.JwtContent(1L, null), 1000L);
        final String token02 = jwtToken.generateToken(new JwtToken.JwtContent(1L, List.of()), 1000L);

        // Then
        assertThat(token01).isNotBlank();
        assertThat(token02).isNotBlank();
    }

    @Test
    void parseToken_whenExpiredToken_thenResult() {
        // Given
        final JwtConfigProperties jwtConfigProperties = new JwtConfigProperties("test", 0);
        final JwtToken jwtToken = new JwtToken(jwtConfigProperties);
        final String token = jwtToken.generateToken(new JwtToken.JwtContent(1L, null), 0L);

        // Then
        Assertions.assertThrows(
                RuntimeException.class,
                () -> jwtToken.parseToken(token)
        );
    }

    @Test
    void parseToken_whenValidToken_thenResult() {
        // Given
        final JwtConfigProperties jwtConfigProperties = new JwtConfigProperties("test", 1);
        final JwtToken jwtToken = new JwtToken(jwtConfigProperties);
        final String token = jwtToken.generateToken(new JwtToken.JwtContent(1L, List.of(Authority.ADMIN, Authority.MANAGER)), System.currentTimeMillis());

        // Then
        final JwtToken.JwtContent content = jwtToken.parseToken(token);

        // Then
        assertThat(content).isNotNull();
        assertThat(content.id()).isEqualTo(1L);
        assertThat(content.authorities()).hasSize(2);
        assertThat(content.authorities()).contains(Authority.ADMIN, Authority.MANAGER);
    }
}
