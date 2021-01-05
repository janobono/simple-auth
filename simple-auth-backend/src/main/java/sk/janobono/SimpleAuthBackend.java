package sk.janobono;

import sk.janobono.config.ConfigProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication(scanBasePackages = {"sk.janobono"})
@EnableConfigurationProperties(ConfigProperties.class)
public class SimpleAuthBackend {

    public static void main(String[] args) {
        SpringApplication.run(SimpleAuthBackend.class, args);
    }

}
