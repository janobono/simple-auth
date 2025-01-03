package sk.janobono.simple.common.exception;

import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import sk.janobono.simple.api.model.ErrorCode;
import sk.janobono.simple.api.model.ErrorMessage;

import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;

@Provider
public class ServiceExceptionMapper implements ExceptionMapper<Throwable> {

    @Override
    public Response toResponse(final Throwable throwable) {
        return switch (throwable) {
            case final ApplicationException applicationException -> mapException(applicationException);
            case final WebApplicationException webApplicationException -> mapException(webApplicationException);
            default -> mapException(throwable);
        };
    }

    private Response mapException(final ApplicationException applicationException) {
        return Response
                .status(Response.Status.BAD_REQUEST)
                .entity(
                        ErrorMessage.builder()
                                .code(applicationException.getCode())
                                .message(applicationException.getMessage())
                                .timestamp(OffsetDateTime.now().truncatedTo(ChronoUnit.MILLIS))
                                .build()
                )
                .build();
    }

    private Response mapException(final WebApplicationException webApplicationException) {
        return Response
                .status(webApplicationException.getResponse().getStatus())
                .entity(
                        ErrorMessage.builder()
                                .code(ErrorCode.UNKNOWN)
                                .message(webApplicationException.getMessage())
                                .timestamp(OffsetDateTime.now().truncatedTo(ChronoUnit.MILLIS))
                                .build()
                )
                .build();
    }

    private Response mapException(final Throwable throwable) {
        return Response
                .serverError()
                .entity(
                        ErrorMessage.builder()
                                .code(ErrorCode.UNKNOWN)
                                .message(throwable.getClass().getName())
                                .timestamp(OffsetDateTime.now().truncatedTo(ChronoUnit.MILLIS))
                                .build()
                )
                .build();
    }
}
