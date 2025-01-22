package sk.janobono.simple;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;
import org.testcontainers.containers.PostgreSQLContainer;
import sk.janobono.simple.api.model.AuthenticationResponse;
import sk.janobono.simple.api.model.SignIn;
import sk.janobono.simple.business.service.MailService;

@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = {
        "spring.sql.init.mode=always",
        "spring.sql.init.schema-locations=file:../db/init.sql"
    }
)
public abstract class BaseTest {

    public static final PostgreSQLContainer<?> postgresDB = new PostgreSQLContainer<>
        ("postgres:alpine")
        .withDatabaseName("app")
        .withUsername("app")
        .withPassword("app");

    static {
        postgresDB.start();
    }

    @Value("${local.server.port}")
    public int serverPort;
    public RestClient restClient;
    @MockBean
    public MailService mailService;
    protected TestMail testMail;

    @DynamicPropertySource
    public static void properties(final DynamicPropertyRegistry registry) throws Exception {
        registry.add("spring.datasource.url", postgresDB::getJdbcUrl);
    }

    @BeforeEach
    public void setUp() {
        restClient = RestClient.create("http://localhost:" + serverPort);

        testMail = new TestMail();
        testMail.mock(mailService);
    }

    public AuthenticationResponse signIn(final String email, final String password) {
        return restClient
            .post()
            .uri(getURI("/auth/sign-in"))
            .contentType(MediaType.APPLICATION_JSON)
            .body(new SignIn(email, password))
            .retrieve().body(AuthenticationResponse.class);
    }

    public URI getURI(final String path) {
        return UriComponentsBuilder.fromHttpUrl("http://localhost:" + serverPort)
            .path("/api" + path).build().toUri();
    }

    public URI getURI(final String path, final Map<String, String> pathVars) {
        return UriComponentsBuilder.fromHttpUrl("http://localhost:" + serverPort)
            .path("/api" + path).buildAndExpand(pathVars).toUri();
    }

    public URI getURI(final String path, final MultiValueMap<String, String> queryParams) {
        return UriComponentsBuilder.fromHttpUrl("http://localhost:" + serverPort)
            .path("/api" + path).queryParams(queryParams).build().toUri();
    }

    public void addToParams(final MultiValueMap<String, String> params, final String key, final String value) {
        Optional.ofNullable(value).ifPresent(v -> params.add(key, v));
    }

    public void addPageableToParams(final MultiValueMap<String, String> params, final Pageable pageable) {
        if (pageable.isPaged()) {
            params.add("page", Integer.toString(pageable.getPageNumber()));
            params.add("size", Integer.toString(pageable.getPageSize()));
            if (pageable.getSort().isSorted()) {
                final StringBuilder sb = new StringBuilder();
                List<Sort.Order> orderList = pageable.getSort().get().filter(Sort.Order::isAscending).collect(Collectors.toList());
                if (!orderList.isEmpty()) {
                    for (final Sort.Order order : orderList) {
                        sb.append(order.getProperty()).append(',');
                    }
                    sb.append("ASC,");
                }
                orderList = pageable.getSort().get().filter(Sort.Order::isDescending).toList();
                if (!orderList.isEmpty()) {
                    for (final Sort.Order order : orderList) {
                        sb.append(order.getProperty()).append(',');
                    }
                    sb.append("DESC,");
                }
                String sort = sb.toString();
                sort = sort.substring(0, sort.length() - 1);
                params.add("sort", sort);
            }
        }
    }
}
