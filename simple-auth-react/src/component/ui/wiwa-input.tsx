import type { InputHTMLAttributes } from 'react';
import { forwardRef } from 'react';
import { twMerge } from 'tailwind-merge';

const WiwaInput = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>((
    {
        className,
        children,
        ...props
    }, ref
) => (
    <input
        ref={ref}
        className={twMerge(`input input-xs xl:input-sm input-bordered w-full ${className ?? ''}`)}
        {...props}
    >
        {children}
    </input>
));

WiwaInput.displayName = 'WiwaInput';

export default WiwaInput;
