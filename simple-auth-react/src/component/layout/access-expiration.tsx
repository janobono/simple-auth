import { useContext, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { AuthContext } from '../../context';
import { REFRESH_TIMEOUT } from '../../context/provider/auth';

const AccessExpiration = () => {
    const navigate = useNavigate();

    const authState = useContext(AuthContext);

    const [show, setShow] = useState(false);

    useEffect(() => {
        if (authState) {
            setShow(authState.timeToAccessExpiration < 3 * REFRESH_TIMEOUT && authState?.user !== undefined);
        } else {
            setShow(false);
        }
    }, [authState, authState?.timeToAccessExpiration]);

    return (!show ? null :
            <div className="alert alert-warning text-xs xl:text-sm">
                <span>Login will expire soon.</span>
                <button
                    className="btn btn-sm normal-case text-xs xl:text-sm"
                    onClick={() => {
                        navigate('/auth/sign-in');
                    }}
                >Refresh
                </button>
            </div>
    )
}

export default AccessExpiration;
