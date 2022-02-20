package sk.janobono.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.server.ResponseStatusException;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Objects;

@ControllerAdvice
public class ControllerAdvisor {

    private static final Logger LOGGER = LoggerFactory.getLogger(ControllerAdvisor.class);

    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<Object> handleResponseStatusException(ResponseStatusException responseStatusException, WebRequest request) {
        LOGGER.warn("handleResponseStatusException({})", responseStatusException.getStatus());
        return new ResponseEntity<>(
                new ExceptionBody(
                        LocalDateTime.now().truncatedTo(ChronoUnit.MILLIS),
                        toMessage(responseStatusException),
                        toStackTrace(responseStatusException)
                ), responseStatusException.getStatus());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Object> handleException(Exception exception, WebRequest request) {
        LOGGER.warn("handleException", exception);
        return new ResponseEntity<>(new ExceptionBody(
                LocalDateTime.now().truncatedTo(ChronoUnit.MILLIS),
                toMessage(exception),
                toStackTrace(exception)
        ), HttpStatus.INTERNAL_SERVER_ERROR);
    }

    private String toMessage(Throwable throwable) {
        String result;
        if (Objects.nonNull(throwable.getLocalizedMessage())) {
            result = throwable.getLocalizedMessage();
        } else {
            result = throwable.toString();
        }
        return result;
    }

    private String toStackTrace(Throwable throwable) {
        StringWriter stringWriter = new StringWriter();
        try (PrintWriter printWriter = new PrintWriter(stringWriter)) {
            throwable.printStackTrace(printWriter);
            printWriter.flush();
        }
        return stringWriter.toString();
    }

    public record ExceptionBody(LocalDateTime timestamp, String message, String stackTrace) {
    }
}
