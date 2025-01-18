package sk.janobono.simple.api;

import jakarta.ws.rs.core.Response;
import sk.janobono.simple.api.model.HealthStatus;

public class ReadyzController implements ReadyzApi {

    @Override
    public Response readyz() {
        return Response.status(Response.Status.OK)
            .entity(HealthStatus.builder().status("OK").build())
            .build();
    }
}
