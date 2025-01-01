package sk.janobono.simple.common.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.NoHandlerFoundException;
import sk.janobono.simple.api.model.ErrorCode;
import sk.janobono.simple.api.model.ErrorMessage;

import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;

@Slf4j
@RestControllerAdvice
public class RestControllerAdvisor {

    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<Object> handleNoHandlerFoundException(final NoHandlerFoundException handlerFoundException) {
        log.warn(handlerFoundException.toString(), handlerFoundException);
        return new ResponseEntity<>(ErrorMessage.builder()
                .code(ErrorCode.NOT_FOUND)
                .message(HttpStatus.NOT_FOUND.getReasonPhrase())
                .timestamp(OffsetDateTime.now().truncatedTo(ChronoUnit.MILLIS))
                .build()
                , HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<Object> handleAuthenticationException(final AuthenticationException authenticationException) {
        log.warn(authenticationException.toString(), authenticationException);
        return new ResponseEntity<>(ErrorMessage.builder()
                .code(ErrorCode.UNAUTHORIZED)
                .message(authenticationException.getMessage())
                .timestamp(OffsetDateTime.now().truncatedTo(ChronoUnit.MILLIS))
                .build()
                , HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Object> handleAccessDeniedException(final AccessDeniedException accessDeniedException) {
        log.warn(accessDeniedException.toString(), accessDeniedException);
        return new ResponseEntity<>(ErrorMessage.builder()
                .code(ErrorCode.FORBIDDEN)
                .message(HttpStatus.FORBIDDEN.getReasonPhrase())
                .timestamp(OffsetDateTime.now().truncatedTo(ChronoUnit.MILLIS))
                .build()
                , HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(ApplicationException.class)
    public ResponseEntity<Object> handleApplicationException(final ApplicationException applicationException) {
        log.warn(applicationException.toString(), applicationException);
        return new ResponseEntity<>(ErrorMessage.builder()
                .code(applicationException.getCode())
                .message(applicationException.getMessage())
                .timestamp(OffsetDateTime.now().truncatedTo(ChronoUnit.MILLIS))
                .build()
                , HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<Object> handleResponseStatusException(final ResponseStatusException responseStatusException) {
        log.warn(responseStatusException.toString(), responseStatusException);
        return new ResponseEntity<>(ErrorMessage.builder()
                .code(ErrorCode.UNKNOWN)
                .message(responseStatusException.getReason())
                .timestamp(OffsetDateTime.now().truncatedTo(ChronoUnit.MILLIS))
                .build()
                , responseStatusException.getStatusCode());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Object> handleException(final Exception exception) {
        log.warn(exception.toString(), exception);
        return new ResponseEntity<>(ErrorMessage.builder()
                .code(ErrorCode.UNKNOWN)
                .message(HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase())
                .timestamp(OffsetDateTime.now().truncatedTo(ChronoUnit.MILLIS))
                .build()
                , HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Object> handleRuntimeException(final RuntimeException runtimeException) {
        log.warn(runtimeException.toString(), runtimeException);
        return new ResponseEntity<>(ErrorMessage.builder()
                .code(ErrorCode.UNKNOWN)
                .message(HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase())
                .timestamp(OffsetDateTime.now().truncatedTo(ChronoUnit.MILLIS))
                .build()
                , HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
