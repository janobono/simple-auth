import { useContext, useState } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { ErrorCode } from '../../api/model/data';
import { simpleEmailValidation, simpleStringValidation } from '../../component/ui';
import WiwaButton from '../../component/ui/wiwa-button';
import WiwaFormError from '../../component/ui/wiwa-form-error';
import WiwaFormInputString from '../../component/ui/wiwa-form-input-string';
import { AuthContext, ErrorContext } from '../../context';

const SignInPage = () => {
    const navigate = useNavigate();

    const authState = useContext(AuthContext);
    const errorState = useContext(ErrorContext);

    const [email, setEmail] = useState('');
    const [emailValid, setEmailValid] = useState(false);
    const [emailValidationMessage, setEmailValidationMessage] = useState<string>();

    const [password, setPassword] = useState('');
    const [passwordValid, setPasswordValid] = useState(false);
    const [passwordValidationMessage, setPasswordValidationMessage] = useState<string>();

    const [formError, setFormError] = useState<string>();

    const isFormValid = (): boolean => {
        return emailValid && passwordValid;
    }

    const handleSubmit = async () => {
        setFormError(undefined);
        if (isFormValid()) {
            const response = await authState?.signIn({email, password});
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
                    case ErrorCode.INVALID_CREDENTIALS:
                        setFormError('Invalid credentials');
                        break;
                    default:
                        errorState?.addError(response?.error);
                        break;
                }
            } else {
                navigate('/');
            }
        }
    }

    return (
        <>
            <div className="flex flex-col justify-center w-full">
                <div className="text-base xl:text-lg font-bold text-center">Sign In</div>
                <div className="text-xs xl:text-sm text-center">
                    <span>or </span>
                    <NavLink
                        className="link"
                        to="/auth/sign-up"
                    >Sign Up</NavLink>
                </div>
            </div>

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
                >
                    <div className="flex justify-end my-1">
                        <NavLink
                            className="link text-xs xl:text-sm"
                            to="/auth/reset-password"
                        >Forgotten password?</NavLink>
                    </div>
                </WiwaFormInputString>

                <div className="flex flex-row justify-end py-2 xl:py-5">
                    <WiwaButton
                        type="submit"
                        className="btn-primary"
                        disabled={authState?.busy || !isFormValid()}
                    >Sign In</WiwaButton>
                </div>

                <WiwaFormError formError={formError}/>
            </form>
        </>
    )
}

export default SignInPage;
