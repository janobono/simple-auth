import { ReactNode } from 'react';

import WiwaInput from './wiwa-input';

const WiwaFormInputString = (
    {
        type = 'text',
        label,
        required = false,
        name,
        placeholder,
        value,
        setValue,
        validate,
        validationMessage,
        children,
        disabled,
        readOnly
    }: {
        type?: 'text' | 'password' | 'email',
        label?: string,
        required?: boolean,
        name?: string,
        placeholder?: string,
        value?: string,
        setValue?: (value: string) => void,
        validate?: (value?: string) => void,
        validationMessage?: string,
        children?: ReactNode,
        disabled?: boolean
        readOnly?: boolean
    }) => {
    return (
        <div className="flex flex-col w-full">
            {label &&
                <label className="label" htmlFor={name}>
                    <span className="label-text text-xs xl:text-sm">{label + (required ? '*' : '')}</span>
                </label>
            }
            <WiwaInput
                type={type}
                id={name}
                name={name}
                placeholder={placeholder}
                value={value}
                onChange={event => {
                    const newValue = event.target.value;
                    if (validate) {
                        validate(newValue);
                    }
                    if (setValue) {
                        setValue(newValue);
                    }
                }}
                onBlur={(event) => {
                    if (!event.currentTarget.contains(event.relatedTarget)) {
                        if (validate) {
                            validate(value);
                        }
                    }
                }}
                disabled={disabled}
                readOnly={readOnly}
            />
            {validationMessage &&
                <label className="label" htmlFor={name}>
                    <span className="label-text-alt text-xs xl:text-sm text-error">{validationMessage}</span>
                </label>
            }
            {children}
        </div>
    )
}

export default WiwaFormInputString;
