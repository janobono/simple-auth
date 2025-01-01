import { ReactNode } from 'react';
import { twMerge } from 'tailwind-merge';

const WiwaFormCheckBox = (
    {
        name,
        value,
        setValue,
        className,
        sizeClassName = 'sm:max-md:checkbox-sm md:max-lg:checkbox-sm lg:max-xl:checkbox-sm',
        disabled = false,
        children
    }: {
        name?: string,
        value: boolean,
        setValue: (value: boolean) => void,
        className?: string,
        sizeClassName?: string,
        disabled?: boolean,
        children?: ReactNode
    }) => {
    return (
        <div className={twMerge(`w-full ${className ?? ''}`)}>
            <input
                type="checkbox"
                id={name}
                name={name}
                checked={value}
                onChange={() => setValue(!value)}
                className={twMerge(`checkbox ${sizeClassName ?? ''}`)}
                disabled={disabled}
            />
            {children}
        </div>
    );
}

export default WiwaFormCheckBox;
