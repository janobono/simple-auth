package sk.janobono;

import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.ResourceUtils;
import sk.janobono.config.ConfigProperties;

import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public abstract class BaseIntegrationTest {

    @Autowired
    public ConfigProperties configProperties;

    @BeforeEach
    public void initDb() {
        // default user
        runSqlScript("app", "clean.sql");
        runSqlScript("app", "init.sql");
        WaitFor.waitForTst(1, () -> runSqlCount("app", "simple_auth_user") == 1L);
    }

    public void runSqlScript(String dbName, String sqlScriptResource) {
        try {
            List<String> commands = new ArrayList<>();
            Class.forName("org.postgresql.Driver");
            try (
                    Connection connection = DriverManager.getConnection(configProperties.databaseUrl() + "/" + dbName, "app", "app");
                    Reader reader = new InputStreamReader(
                            ResourceUtils.getURL("classpath:" + sqlScriptResource).openStream(), StandardCharsets.UTF_8
                    );
                    LineNumberReader lineReader = new LineNumberReader(reader)
            ) {
                String line;
                StringBuilder command = new StringBuilder();
                while ((line = lineReader.readLine()) != null) {
                    String trimmedLine = line.trim();
                    if (trimmedLine.endsWith(";")) {
                        commands.add(command.append(line.substring(0, line.lastIndexOf(";"))).append(" ").toString());
                        command = new StringBuilder();
                    } else {
                        command.append(line).append(" ");
                    }
                }
                for (String cmd : commands) {
                    try (Statement statement = connection.createStatement()) {
                        statement.execute(cmd);
                    }
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public long runSqlCount(String dbName, String tableName) {
        try {
            Class.forName("org.postgresql.Driver");
            try (
                    Connection connection = DriverManager.getConnection(configProperties.databaseUrl() + "/" + dbName, "app", "app");
                    Statement statement = connection.createStatement()
            ) {
                ResultSet resultSet = statement.executeQuery("SELECT COUNT(*) FROM " + tableName);
                if (resultSet.next()) {
                    return resultSet.getLong(1);
                }
                return -1L;
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
