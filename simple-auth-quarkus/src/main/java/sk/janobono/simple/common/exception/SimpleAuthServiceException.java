package sk.janobono.simple.common.exception;

import java.text.MessageFormat;
import sk.janobono.simple.api.model.ErrorCode;

public enum SimpleAuthServiceException {

    UNAUTHORIZED,
    AUTHORITY_NOT_FOUND,
    INVALID_CAPTCHA,
    INVALID_CREDENTIALS,
    UNSUPPORTED_VALIDATION_TOKEN,
    USER_EMAIL_IS_USED,
    USER_NOT_CONFIRMED,
    USER_IS_DISABLED,
    USER_NOT_FOUND;

    public ApplicationException exception(final String pattern, final Object... arguments) {
        return exception(null, pattern, arguments);
    }

    public ApplicationException exception(final Throwable cause, final String pattern, final Object... arguments) {
        return new ApplicationException(ErrorCode.fromValue(this.name()), MessageFormat.format(pattern, arguments), cause);
    }
}
