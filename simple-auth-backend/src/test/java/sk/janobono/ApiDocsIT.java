package sk.janobono;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.nio.file.Files;
import java.nio.file.Paths;

import static org.assertj.core.api.Assertions.assertThat;

public class ApiDocsIT extends BaseIntegrationTest {

    @Test
    public void apiDocs() throws Exception {
        MvcResult mvcResult = mvc.perform(MockMvcRequestBuilders.get("/v3/api-docs.yaml")).andReturn();
        assertThat(mvcResult.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
        Files.write(Paths.get(System.getProperty("java.io.tmpdir"), "api-docs.yml"),
                mvcResult.getResponse().getContentAsString().getBytes());
    }
}
