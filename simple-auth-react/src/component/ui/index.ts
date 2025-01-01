export const EMAIL_REGEX = new RegExp(/^[^\s@]+@[^\s@]+\.[^\s@]+$/);

export const isBlank = (value?: string) => {
    return value === undefined || value.trim().length === 0;
}

export const simpleStringValidation = (message: string, setMessage: (message?: string) => void, setValid: (valid: boolean) => void, value?: string) => {
    setValid(false);
    setMessage(undefined);
    if (isBlank(value)) {
        setMessage(message);
        return;
    }
    setValid(true);
}

export const simpleEmailValidation = (setMessage: (message?: string) => void, setValid: (valid: boolean) => void, value?: string) => {
    setValid(false);
    setMessage(undefined);
    if (isBlank(value)) {
        setMessage('Email is required');
        return;
    }
    if (!EMAIL_REGEX.test(value || '')) {
        setMessage('Invalid email');
        return;
    }
    setValid(true);
}

export const simpleCaptchaValidation = (setMessage: (message?: string) => void, setValid: (valid: boolean) => void, value?: string) => {
    setValid(false);
    setMessage(undefined);
    if (isBlank(value)) {
        setMessage('Captcha is required');
        return;
    }
    setValid(true);
}

export const formatBoolean = (value?: boolean) => {
    if (value !== undefined) {
        return value ? 'Yes' : 'No';
    }
    return '';
}

export const formatNumber = (value?: number) => {
    if (value !== undefined) {
        return value.toString();
    } else {
        return '';
    }
}
