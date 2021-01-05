package sk.janobono;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.benas.randombeans.api.EnhancedRandom;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.testcontainers.containers.PostgreSQLContainer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext
public abstract class BaseIntegrationTest {

    public static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:12-alpine");

    @BeforeAll
    public static void startContainers() {
        postgres.start();
        System.setProperty("SIMPLE_AUTH_DB_URL", postgres.getJdbcUrl());
        System.setProperty("SIMPLE_AUTH_DB_USER", postgres.getUsername());
        System.setProperty("SIMPLE_AUTH_DB_PASS", postgres.getPassword());
    }

    @AfterAll
    public static void stopContainers() {
        postgres.stop();
    }

    public EnhancedRandom enhancedRandom = TestEnhancedRandomBuilder.build();

    @Autowired
    public MockMvc mvc;

    @Autowired
    public Flyway flyway;

    @Autowired
    public WebApplicationContext webApplicationContext;

    @Autowired
    public ObjectMapper objectMapper;

    @BeforeEach
    public void setUp() {
        flyway.clean();
        flyway.migrate();
        mvc = MockMvcBuilders
                .webAppContextSetup(webApplicationContext)
                .build();
    }

    public String mapToJson(Object obj) throws JsonProcessingException {
        return objectMapper.writeValueAsString(obj);
    }

    public <T> T mapFromJson(String json, Class<T> clazz)
            throws IOException {
        return objectMapper.readValue(json, clazz);
    }

    public <T> List<T> mapListFromJson(String json, Class<T> paramClazz) throws Exception {
        return getListFromNode(objectMapper.readTree(json), paramClazz);
    }

    public <T> Page<T> mapPagedResponse(String json, Class<T> paramClazz)
            throws IOException {
        JsonNode parent = objectMapper.readTree(json);
        return new PageImpl<>(
                getListFromNode(parent.get("content"), paramClazz),
                PageRequest.of(
                        parent.get("pageable").get("pageNumber").asInt(),
                        parent.get("pageable").get("pageSize").asInt()),
                parent.get("totalElements").asLong());
    }

    public <T> List<T> getListFromNode(JsonNode node, Class<T> clazz) throws IOException {
        List<T> content = new ArrayList<>();
        for (JsonNode val : node) {
            content.add(objectMapper.readValue(val.traverse(), clazz));
        }
        return content;
    }
}
