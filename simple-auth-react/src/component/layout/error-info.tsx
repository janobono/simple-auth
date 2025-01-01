import { useContext } from 'react';
import { ErrorMessage } from '../../api/model/data';

import { ErrorContext } from '../../context';

const ErrorInfo = () => {
    const errorState = useContext(ErrorContext);

    return (
        <>
            {errorState?.data.map((item, index) =>
                <ApplicationErrorPanel key={index} index={index} applicationError={item}/>
            )}
        </>
    )
}

export default ErrorInfo;

const ApplicationErrorPanel = ({index, applicationError}: { index: number, applicationError: ErrorMessage }) => {
    const errorState = useContext(ErrorContext);

    return (
        <div className="alert alert-error text-xs xl:text-sm">
            <span>We apologize. An error occurred.</span>
            <span>{`${applicationError.code}: ${applicationError.message} [${applicationError.timestamp}]`}</span>
            <button
                className="btn btn-sm normal-case text-xs xl:text-sm"
                onClick={() => errorState?.removeError(index)}
            >Zavrieť
            </button>
        </div>
    )
}
