import { useContext, useEffect, useRef, useState } from 'react';
import { useParams } from 'react-router-dom';
import { ErrorCode } from '../api/model/data';
import WiwaSpinner from '../component/ui/wiwa-spinner';
import { AuthContext, ErrorContext } from '../context';

const ConfirmPage = () => {
    const {token} = useParams();

    const authState = useContext(AuthContext);
    const errorState = useContext(ErrorContext);

    const done = useRef(false);
    const [message, setMessage] = useState<string>();

    useEffect(() => {
        if (done.current) {
            return;
        }
        done.current = true;

        if (token) {
            const action = async () => {
                const response = await authState?.confirm({token});
                if (response?.error) {
                    switch (response?.error.code) {
                        case ErrorCode.UNSUPPORTED_VALIDATION_TOKEN:
                            setMessage('Invalid request.');
                            break;
                        default:
                            errorState?.addError(response?.error);
                            break;
                    }
                } else {
                    setMessage('Your request has been processed.');
                }
            }
            action().then();
        }
    }, [token]);

    return (
        <div className="container p-5 mx-auto">
            <div className="flex flex-col items-center justify-center">
                <div className="text-lg font-bold text-center pb-5">Request processing</div>
                {authState?.busy ?
                    <WiwaSpinner/>
                    :
                    <span className="font-mono text-xl">{message}</span>
                }
            </div>
        </div>
    )
}

export default ConfirmPage;
