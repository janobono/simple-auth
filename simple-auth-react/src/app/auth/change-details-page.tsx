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

const ChangeDetailsPage = () => {
    const navigate = useNavigate();

    const authState = useContext(AuthContext);
    const errorState = useContext(ErrorContext);

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

    const isFormValid = (): boolean => {
        return firstNameValid && lastNameValid && captchaValid;
    }

    const handleSubmit = async () => {
        setFormError(undefined);
        if (isFormValid()) {
            const response = await authState?.changeUserDetails({
                firstName,
                lastName,
                captchaText,
                captchaToken
            });
            if (response?.error) {
                switch (response?.error.code) {
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
                navigate('/');
            }
        }
    }

    useEffect(() => {
        const user = authState?.user;
        if (user) {
            setFirstName(user.firstName || '');
            setLastName(user.lastName || '');
        }
    }, [authState?.user]);

    return (
        <AuthDefender>
            <WiwaBreadcrumb breadcrumbs={[
                {key: 0, label: 'User'},
                {
                    key: 1,
                    label: 'Account details',
                    to: '/auth/change-details'
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
                    label="First name"
                    required={true}
                    name="firstName"
                    placeholder="Enter first name"
                    value={firstName}
                    setValue={setFirstName}
                    validate={(value) => simpleStringValidation('First name is required', setFirstValidationMessage, setFirstNameValid, value)}
                    validationMessage={firstValidationMessage}
                />

                <WiwaFormInputString
                    label="Last name"
                    required={true}
                    name="lastName"
                    placeholder="Enter last name"
                    value={lastName}
                    setValue={setLastName}
                    validate={(value) => simpleStringValidation('Last name is required', setLastNameValidationMessage, setLastNameValid, value)}
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
                    >Ok</WiwaButton>
                </div>

                <WiwaFormError formError={formError}/>
            </form>
        </AuthDefender>
    )
}

export default ChangeDetailsPage;
