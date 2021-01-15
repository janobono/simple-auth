package sk.janobono.api.controller;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import sk.janobono.BaseIntegrationTest;

import static org.assertj.core.api.Assertions.assertThat;

public class HealthControllerIT extends BaseIntegrationTest {

    @Test
    public void health() throws Exception {
        MvcResult mvcResult = mvc.perform(MockMvcRequestBuilders.get("/health")).andReturn();
        assertThat(mvcResult.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
        assertThat(mvcResult.getResponse().getContentAsString()).isNotNull();
        assertThat(mvcResult.getResponse().getContentAsString()).isEqualTo("OK");
    }
}
