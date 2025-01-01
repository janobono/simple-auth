import { useContext, useEffect, useState } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { ErrorCode } from '../../api/model/data';
import { simpleCaptchaValidation, simpleEmailValidation, simpleStringValidation } from '../../component/ui';
import WiwaButton from '../../component/ui/wiwa-button';
import WiwaFormCaptcha from '../../component/ui/wiwa-form-captcha';
import WiwaFormError from '../../component/ui/wiwa-form-error';
import WiwaFormInputString from '../../component/ui/wiwa-form-input-string';
import { AuthContext, ErrorContext } from '../../context';

const SignUpPage = () => {
    const navigate = useNavigate();

    const authState = useContext(AuthContext);
    const errorState = useContext(ErrorContext);

    const [email, setEmail] = useState('');
    const [emailValid, setEmailValid] = useState(false);
    const [emailValidationMessage, setEmailValidationMessage] = useState<string>();

    const [password, setPassword] = useState('');
    const [passwordValid, setPasswordValid] = useState(false);
    const [passwordValidationMessage, setPasswordValidationMessage] = useState<string>();

    const [passwordConfirmation, setPasswordConfirmation] = useState('');
    const [passwordConfirmationValid, setPasswordConfirmationValid] = useState(false);
    const [passwordConfirmationValidationMessage, setPasswordConfirmationValidationMessage] = useState<string>();

    const validatePasswordConfirmation = (value?: string) => simpleStringValidation('Password confirmation is required', setPasswordConfirmationValidationMessage, setPasswordConfirmationValid, value);

    useEffect(() => {
        if (password !== passwordConfirmation) {
            if (passwordConfirmationValid) {
                setPasswordConfirmationValidationMessage('Password confirmation and password are different');
                setPasswordConfirmationValid(false);
            }
        } else {
            if (password.length > 0 && passwordConfirmation.length > 0) {
                validatePasswordConfirmation(passwordConfirmation);
            }
        }
    }, [password, passwordConfirmation, passwordConfirmationValid]);

    const [firstName, setFirstName] = useState('');
    const [firstNameValid, setFirstNameValid] = useState(false);
    const [firstValidationMessage, setFirstValidationMessage] = useState<string>();

    const [lastName, setLastName] = useState('');
    const [lastNameValid, setLastNameValid] = useState(false);
    const [lastNameValidationMessage, setLastNameValidationMessage] = useState<string>();

    const [captchaText, setCaptchaText] = useState('');
    const [captchaToken, setCaptchaToken] = useState('');
    const [captchaValid, setCaptchaValid] = useState(false);
    const [captchaValidationMessage, setCaptchaValidationMessage] = useState<string>();

    const [formError, setFormError] = useState<string>();
    const [message, setMessage] = useState<string>();

    const isFormValid = (): boolean => {
        return emailValid && passwordValid && passwordConfirmationValid && firstNameValid
            && lastNameValid && captchaValid;
    }

    const handleSubmit = async () => {
        setFormError(undefined);
        if (isFormValid()) {
            const response = await authState?.signUp({
                email,
                password,
                firstName,
                lastName,
                captchaText,
                captchaToken
            });
            if (response?.error) {
                switch (response?.error.code) {
                    case ErrorCode.USER_EMAIL_IS_USED:
                        setFormError('Email is used');
                        break;
                    case ErrorCode.INVALID_CAPTCHA:
                        setFormError('Invalid captcha');
                        break;
                    default:
                        errorState?.addError(response?.error);
                        break;
                }
            } else {
                setMessage('Account created. Check activation mail please.');
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
            <div className="flex flex-col justify-center w-full">
                <div className="text-base xl:text-lg font-bold text-center">Sign Up</div>
                <div className="text-xs xl:text-sm font-normal text-center">
                    <span>or </span>
                    <NavLink
                        className="link text-xs xl:text-sm"
                        to="/auth/sign-in"
                    >Sign In</NavLink>
                </div>
            </div>

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

                    <div className="flex flex-col md:flex-row gap-2 ">
                        <WiwaFormInputString
                            type="password"
                            label="Password"
                            required={true}
                            name="password"
                            placeholder="Enter password"
                            value={password}
                            setValue={setPassword}
                            validate={(value) => simpleStringValidation('Password is required', setPasswordValidationMessage, setPasswordValid, value)}
                            validationMessage={passwordValidationMessage}
                        />

                        <WiwaFormInputString
                            type="password"
                            label="Password confirmation"
                            required={true}
                            name="passwordConfirmation"
                            placeholder="Enter password confirmation"
                            value={passwordConfirmation}
                            setValue={setPasswordConfirmation}
                            validate={validatePasswordConfirmation}
                            validationMessage={passwordConfirmationValidationMessage}
                        />
                    </div>

                    <WiwaFormInputString
                        label="First name"
                        required={true}
                        name="firstName"
                        placeholder="Enter first name"
                        value={firstName}
                        setValue={setFirstName}
                        validate={(value) => simpleStringValidation('First name required', setFirstValidationMessage, setFirstNameValid, value)}
                        validationMessage={firstValidationMessage}
                    />

                    <WiwaFormInputString
                        label="Last name"
                        required={true}
                        name="lastName"
                        placeholder="Enter last name"
                        value={lastName}
                        setValue={setLastName}
                        validate={(value) => simpleStringValidation('Last name required', setLastNameValidationMessage, setLastNameValid, value)}
                        validationMessage={lastNameValidationMessage}
                    />

                    <WiwaFormCaptcha
                        valueName="captchaText"
                        tokenName="captchaToken"
                        value={captchaText}
                        setValue={setCaptchaText}
                        token={captchaToken}
                        setToken={setCaptchaToken}
                        validate={(value) => simpleCaptchaValidation(setCaptchaValidationMessage, setCaptchaValid, value)}
                        validationMessage={captchaValidationMessage}
                    />

                    <div className="flex flex-row justify-end py-2 xl:py-5">
                        <WiwaButton
                            type="submit"
                            className="btn-primary"
                            disabled={authState?.busy || !isFormValid()}
                        >Sign Up</WiwaButton>
                    </div>

                    <WiwaFormError formError={formError}/>
                </form>
            }
        </>
    )
}

export default SignUpPage;
