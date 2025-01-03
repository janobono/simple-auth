package sk.janobono.simple.api;

import org.springframework.web.bind.annotation.RestController;
import sk.janobono.simple.api.model.HealthStatus;

@RestController
public class HealthController implements LivezApi, ReadyzApi {

    @Override
    public HealthStatus livez() {
        return HealthStatus.builder().status("OK").build();
    }

    @Override
    public HealthStatus readyz() {
        return HealthStatus.builder().status("OK").build();
    }
}
