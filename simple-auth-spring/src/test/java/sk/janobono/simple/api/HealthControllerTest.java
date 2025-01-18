package sk.janobono.simple.api;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import sk.janobono.simple.BaseTest;
import sk.janobono.simple.api.model.HealthStatus;

class HealthControllerTest extends BaseTest {

    @Test
    void fullTest() {
        final ResponseEntity<HealthStatus> livez = restClient.get()
            .uri(getURI("/livez"))
            .retrieve()
            .toEntity(HealthStatus.class);
        assertThat(livez.getBody()).isEqualTo(HealthStatus.builder().status("OK").build());
        assertThat(livez.getStatusCode()).isEqualTo(HttpStatus.OK);

        final ResponseEntity<HealthStatus> readyz = restClient.get()
            .uri(getURI("/readyz"))
            .retrieve()
            .toEntity(HealthStatus.class);
        assertThat(readyz.getBody()).isEqualTo(HealthStatus.builder().status("OK").build());
        assertThat(readyz.getStatusCode()).isEqualTo(HttpStatus.OK);
    }
}
