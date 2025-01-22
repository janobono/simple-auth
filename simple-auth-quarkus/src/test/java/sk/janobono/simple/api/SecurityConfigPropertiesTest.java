package sk.janobono.simple.api;

import static io.restassured.RestAssured.given;
import static jakarta.ws.rs.core.Response.Status.FORBIDDEN;
import static jakarta.ws.rs.core.Response.Status.OK;
import static jakarta.ws.rs.core.Response.Status.UNAUTHORIZED;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

@QuarkusTest
class SecurityConfigPropertiesTest {

    @Test
    void fullTest() {
        given()
            .contentType("application/json")
            .when()
            .get("/livez")
            .then()
            .statusCode(OK.getStatusCode())
            .extract().response();

        given()
            .contentType("application/json")
            .when()
            .get("/readyz")
            .then()
            .statusCode(OK.getStatusCode())
            .extract().response();

        given()
            .contentType("application/json")
            .when()
            .get("/captcha")
            .then()
            .statusCode(OK.getStatusCode())
            .extract().response();

        given()
            .contentType("application/json")
            .when()
            .get("/auth/user-detail")
            .then()
            .statusCode(UNAUTHORIZED.getStatusCode())
            .extract().response();

        given()
            .contentType("application/json")
            .when()
            .get("/users/1")
            .then()
            .statusCode(UNAUTHORIZED.getStatusCode())
            .extract().response();
    }
}
