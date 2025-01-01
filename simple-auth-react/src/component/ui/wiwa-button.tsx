import type { ButtonHTMLAttributes } from 'react';
import { twMerge } from 'tailwind-merge';

interface Props extends ButtonHTMLAttributes<HTMLButtonElement> {
    sizeClassName?: string;
}

const WiwaButton = (
    {
        type = 'button',
        sizeClassName = 'sm:max-md:btn-sm md:max-lg:btn-sm lg:max-xl:btn-sm',
        disabled = false,
        className,
        children,
        ...props
    }: Props) => {
    return (
        <button
            type={type}
            disabled={disabled}
            className={twMerge(`btn ${sizeClassName ?? ''} ${className ?? ''}`)}
            {...props}
        >
            {children}
        </button>
    )
}

export default WiwaButton;
