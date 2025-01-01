package sk.janobono.simple.common.exception;

import lombok.Getter;
import sk.janobono.simple.api.model.ErrorCode;

@Getter
public class ApplicationException extends RuntimeException {

    private final ErrorCode code;

    public ApplicationException(final ErrorCode code, final String message, final Throwable cause) {
        super(message, cause);
        this.code = code;
    }
}
