package sk.janobono.simple.api;

import static io.restassured.RestAssured.given;
import static jakarta.ws.rs.core.Response.Status.OK;
import static org.assertj.core.api.Assertions.assertThat;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import org.junit.jupiter.api.Test;
import sk.janobono.simple.api.model.HealthStatus;

@QuarkusTest
class LivezControllerTest {

    @Test
    void fullTest() {
        final Response response = given()
            .contentType("application/json")
            .when()
            .get("/livez")
            .then()
            .statusCode(OK.getStatusCode())
            .extract().response();

        final HealthStatus healthStatus = response.getBody().as(HealthStatus.class);
        assertThat(healthStatus.getStatus()).isEqualTo("OK");
    }
}