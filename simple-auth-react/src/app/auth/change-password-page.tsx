import { useContext, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ErrorCode } from '../../api/model/data';
import AuthDefender from '../../component/layout/auth-defender';
import { simpleCaptchaValidation, simpleStringValidation } from '../../component/ui';
import WiwaBreadcrumb from '../../component/ui/wiwa-breadcrumb';
import WiwaButton from '../../component/ui/wiwa-button';
import WiwaFormCaptcha from '../../component/ui/wiwa-form-captcha';
import WiwaFormError from '../../component/ui/wiwa-form-error';
import WiwaFormInputString from '../../component/ui/wiwa-form-input-string';
import { AuthContext, ErrorContext } from '../../context';

const ChangePasswordPage = () => {
    const navigate = useNavigate();

    const authState = useContext(AuthContext);
    const errorState = useContext(ErrorContext);

    const [oldPassword, setOldPassword] = useState('');
    const [oldPasswordValid, setOldPasswordValid] = useState(false);
    const [oldPasswordValidationMessage, setOldPasswordValidationMessage] = useState<string>();

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

    const [captchaText, setCaptchaText] = useState('');
    const [captchaToken, setCaptchaToken] = useState('');
    const [captchaValid, setCaptchaValid] = useState(false);
    const [captchaValidationMessage, setCaptchaValidationMessage] = useState<string>();

    const [formError, setFormError] = useState<string>();

    const isFormValid = (): boolean => {
        return oldPasswordValid && passwordValid && passwordConfirmationValid && captchaValid;
    }

    const handleSubmit = async () => {
        setFormError(undefined);
        if (isFormValid()) {
            const response = await authState?.changePassword({
                oldPassword,
                newPassword: password,
                captchaText,
                captchaToken
            });
            if (response?.error) {
                switch (response?.error.code) {
                    case ErrorCode.USER_IS_DISABLED:
                        setFormError('User is disabled');
                        break;
                    case ErrorCode.INVALID_CREDENTIALS:
                        setFormError('Invalid credentials');
                        break;
                    case ErrorCode.INVALID_CAPTCHA:
                        setFormError('Invalid captcha');
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
        <AuthDefender>
            <WiwaBreadcrumb breadcrumbs={[
                {key: 0, label: 'User'},
                {
                    key: 1,
                    label: 'Change password',
                    to: '/auth/change-password'
                }
            ]}/>

            <form
                className="w-full max-w-sm xl:max-w-md"
                onSubmit={(event) => {
                    event.preventDefault();
                    handleSubmit().then();
                }}
                noValidate
            >

                <WiwaFormInputString
                    type="password"
                    label="Old password"
                    required={true}
                    name="oldPassword"
                    placeholder="Enter old password"
                    value={oldPassword}
                    setValue={setOldPassword}
                    validate={(value) => simpleStringValidation('Old password is required', setOldPasswordValidationMessage, setOldPasswordValid, value)}
                    validationMessage={oldPasswordValidationMessage}
                />

                <WiwaFormInputString
                    type="password"
                    label="New password"
                    required={true}
                    name="password"
                    placeholder="Enter new password"
                    value={password}
                    setValue={setPassword}
                    validate={(value) => simpleStringValidation('New password is required', setPasswordValidationMessage, setPasswordValid, value)}
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
                    >Ok</WiwaButton>
                </div>

                <WiwaFormError formError={formError}/>
            </form>
        </AuthDefender>
    )
}

export default ChangePasswordPage;
