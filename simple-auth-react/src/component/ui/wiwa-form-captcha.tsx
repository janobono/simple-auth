import { useCallback, useEffect, useState } from 'react';
import { RefreshCw } from 'react-feather';
import { getCaptcha } from '../../api/controller/captcha';

import WiwaButton from './wiwa-button';
import WiwaInput from './wiwa-input';
import WiwaSpinner from './wiwa-spinner';

const WiwaFormCaptcha = (
    {
        required = true,
        valueName,
        tokenName,
        value,
        setValue,
        token,
        setToken,
        validate,
        validationMessage
    }: {
        required?: boolean,
        valueName?: string,
        tokenName?: string,
        value?: string,
        setValue: (value: string) => void,
        token?: string,
        setToken: (value: string) => void,
        validate: (value?: string) => void,
        validationMessage?: string
    }) => {

    const [busy, setBusy] = useState(false);
    const [error, setError] = useState(true);
    const [image, setImage] = useState('');

    useEffect(() => {
        reFetch().then();
    }, []);

    const reFetch = useCallback(async () => {
        setBusy(true);
        setError(false);
        try {
            const response = await getCaptcha();
            if (response?.data) {
                if (setToken) {
                    setToken(response.data.captchaToken || '');
                }
                setImage(response.data.captchaImage || '');
            } else {
                setError(true);
            }
        } catch (error) {
            console.log(error);
            setError(true);
        } finally {
            setBusy(false);
        }
    }, [setToken])

    return (
        <div className="flex flex-col w-full">
            <input type="hidden" id={tokenName} name={tokenName} value={token}/>
            <label className="label" htmlFor={valueName}>
                <span
                    className="label-text text-xs xl:text-sm">{'Captcha' + (required ? '*' : '')}</span>
            </label>

            <WiwaInput
                type="text"
                id={valueName}
                name={valueName}
                placeholder="Enter captcha"
                value={value}
                onChange={event => {
                    const newValue = event.target.value;
                    if (validate) {
                        validate(newValue);
                    }
                    setValue(newValue);
                }}
                onBlur={(event) => {
                    if (!event.currentTarget.contains(event.relatedTarget)) {
                        if (validate) {
                            validate(value);
                        }
                    }
                }}
            />

            {busy ?
                <WiwaSpinner/>
                :
                <div className="flex-1 flex flex-wrap pt-1 xl:pt-2">
                    {error ?
                        <div
                            className="font-normal flex-1 text-xl xl:text-sm text-error align-middle">
                            "Load captcha error"
                        </div>
                        :
                        <img
                            className="flex-1 object-fill rounded-lg h-8 xl:h-12"
                            src={image}
                            alt="captcha"
                        />
                    }
                    <WiwaButton
                        className="btn-sm md:btn-md"
                        title="Load captcha"
                        onClick={() => reFetch()}
                    >
                        <RefreshCw size="16"/>
                    </WiwaButton>
                </div>
            }

            {validationMessage &&
                <label className="label" htmlFor={valueName}>
                    <span className="label-text-alt text-xs xl:text-sm text-error">{validationMessage}</span>
                </label>
            }
        </div>
    )
}

export default WiwaFormCaptcha;
