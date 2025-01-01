import { useContext, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ErrorCode } from '../../api/model/data';
import { simpleEmailValidation } from '../../component/ui';
import WiwaButton from '../../component/ui/wiwa-button';
import WiwaFormCaptcha from '../../component/ui/wiwa-form-captcha';
import WiwaFormError from '../../component/ui/wiwa-form-error';
import WiwaFormInputString from '../../component/ui/wiwa-form-input-string';
import { AuthContext, ErrorContext } from '../../context';

const ResetPasswordPage = () => {
    const navigate = useNavigate();

    const authState = useContext(AuthContext);
    const errorState = useContext(ErrorContext);

    const [email, setEmail] = useState('');
    const [emailValid, setEmailValid] = useState(false);
    const [emailValidationMessage, setEmailValidationMessage] = useState<string>();

    const [captchaText, setCaptchaText] = useState('');
    const [captchaToken, setCaptchaToken] = useState('');
    const [captchaValid, setCaptchaValid] = useState(false);
    const [captchaValidationMessage, setCaptchaValidationMessage] = useState<string>();

    const validateCaptcha = (value?: string) => {
        setCaptchaValid(false);
        setCaptchaValidationMessage(undefined);
        if (value === undefined || value.trim().length === 0) {
            setCaptchaValidationMessage('Captcha is required');
            return;
        }
        setCaptchaValid(true);
    }

    const [formError, setFormError] = useState<string>();
    const [message, setMessage] = useState<string>();

    const isFormValid = (): boolean => {
        return emailValid && captchaValid;
    }

    const handleSubmit = async () => {
        setMessage(undefined);
        setFormError(undefined);
        if (isFormValid()) {
            const response = await authState?.resetPassword({email, captchaText, captchaToken});
            if (response?.error) {
                switch (response?.error.code) {
                    case ErrorCode.USER_NOT_FOUND:
                        setFormError('User not found');
                        break;
                    case ErrorCode.USER_NOT_CONFIRMED:
                        setFormError('User not confirmed');
                        break;
                    case ErrorCode.USER_IS_DISABLED:
                        setFormError('User is disabled');
                        break;
                    case ErrorCode.INVALID_CAPTCHA:
                        setFormError('Invalid captcha');
                        break;
                    default:
                        errorState?.addError(response?.error);
                        break;
                }
            } else {
                setMessage('Password activation mail send.');
            }
        }
    }

    useEffect(() => {
        const user = authState?.user;
        if (user) {
            navigate('/');
        }
    }, [authState?.user, navigate]);

    return (
        <>
            <div className="text-base xl:text-lg font-bold text-center">Zabudnuté heslo</div>
            {message ?
                <div className="w-full max-w-sm xl:max-w-md text-xs xl:text-sm pt-2">{message}</div>
                :
                <form
                    className="w-full max-w-sm xl:max-w-md"
                    onSubmit={(event) => {
                        event.preventDefault();
                        handleSubmit().then();
                    }}
                    noValidate
                >

                    <WiwaFormInputString
                        type="email"
                        label="Email"
                        required={true}
                        name="email"
                        placeholder="Enter email"
                        value={email}
                        setValue={setEmail}
                        validate={(value) => simpleEmailValidation(setEmailValidationMessage, setEmailValid, value)}
                        validationMessage={emailValidationMessage}
                    />

                    <WiwaFormCaptcha
                        valueName="captchaText"
                        tokenName="captchaToken"
                        value={captchaText}
                        setValue={setCaptchaText}
                        token={captchaToken}
                        setToken={setCaptchaToken}
                        validate={validateCaptcha}
                        validationMessage={captchaValidationMessage}
                    />

                    <div className="flex flex-row justify-end py-2 xl:py-5">
                        <WiwaButton
                            type="submit"
                            className="btn-primary"
                            disabled={authState?.busy || !isFormValid()}
                        >Ok</WiwaButton>
                    </div>

                    <WiwaFormError formError={formError}/>
                </form>
            }
        </>
    )
}

export default ResetPasswordPage;
