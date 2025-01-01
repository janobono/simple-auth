import type { HTMLAttributes } from 'react';
import { forwardRef } from 'react';
import { twMerge } from 'tailwind-merge';

const WiwaSpinner = forwardRef<HTMLDivElement, HTMLAttributes<HTMLDivElement>>(
    (
        {
            children,
            className,
            ...props
        }, ref
    ) => (
        <div
            ref={ref}
            className={twMerge(`w-8 xl:w-12 h-8 xl:h-12 border-2 xl:border-4 rounded-full animate-spin border-solid border-base-500 border-t-transparent ${className ?? ''}`)}
            {...props}
        >
            {children}
        </div>
    ));

WiwaSpinner.displayName = 'WiwaSpinner';

export default WiwaSpinner;
