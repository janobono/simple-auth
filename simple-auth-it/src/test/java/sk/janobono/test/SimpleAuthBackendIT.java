package sk.janobono.test;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import sk.janobono.BaseIntegrationTest;
import sk.janobono.client.AuthApi;
import sk.janobono.client.HealthApi;
import sk.janobono.config.ConfigProperties;
import sk.janobono.model.SimpleAuthAuthenticationRequest;
import sk.janobono.model.SimpleAuthAuthenticationResponse;
import sk.janobono.model.SimpleAuthUser;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
public class SimpleAuthBackendIT extends BaseIntegrationTest {

    @Autowired
    public ConfigProperties configProperties;

    @Autowired
    public HealthApi healthApi;

    @Autowired
    public AuthApi authApi;

    @Test
    public void health() {
        healthApi.getApiClient().setBasePath(configProperties.simpleAuthBackendUrl());
        String result = healthApi.health();
        assertThat(result).isEqualTo("OK");
    }

    @Test
    public void api() {
        authApi.getApiClient().setBasePath(configProperties.simpleAuthBackendUrl());

        SimpleAuthAuthenticationRequest simpleAuthAuthenticationRequest = new SimpleAuthAuthenticationRequest();
        simpleAuthAuthenticationRequest.setUsername("trevor.ochmonek.dev");
        simpleAuthAuthenticationRequest.setPassword("MelmacAlf+456");
        SimpleAuthAuthenticationResponse simpleAuthAuthenticationResponse = authApi.authenticate(simpleAuthAuthenticationRequest);
        assertThat(simpleAuthAuthenticationResponse).isNotNull();

        authApi.getApiClient().addDefaultHeader("Authorization", "Bearer " + simpleAuthAuthenticationResponse.getToken());

        SimpleAuthUser simpleAuthUser = authApi.currentUser();
        assertThat(simpleAuthUser.getUsername()).isEqualTo("trevor.ochmonek.dev");
        assertThat(simpleAuthUser.getAttributes().get("hotel_code")).isEqualTo("simple-123");
    }
}
