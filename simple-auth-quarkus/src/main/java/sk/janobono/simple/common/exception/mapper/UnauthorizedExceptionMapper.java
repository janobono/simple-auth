package sk.janobono.simple.common.exception.mapper;

import io.quarkus.security.UnauthorizedException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import sk.janobono.simple.api.model.ErrorCode;
import sk.janobono.simple.api.model.ErrorMessage;

@Provider
public class UnauthorizedExceptionMapper implements ExceptionMapper<UnauthorizedException> {

  @Override
  public Response toResponse(final UnauthorizedException unauthorizedException) {
    return Response
        .status(Status.UNAUTHORIZED)
        .entity(
            ErrorMessage.builder()
                .code(ErrorCode.UNAUTHORIZED)
                .message(unauthorizedException.getMessage())
                .timestamp(OffsetDateTime.now().truncatedTo(ChronoUnit.MILLIS))
                .build()
        )
        .build();
  }
}
