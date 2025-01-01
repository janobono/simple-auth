import { ReactNode, useContext, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Authority } from '../../api/model/data';

import { AuthContext } from '../../context';

const AuthDefender = ({children, authority}: { children?: ReactNode, authority?: Authority }) => {
    const navigate = useNavigate();
    const authState = useContext(AuthContext);

    useEffect(() => {
        if (authState?.timeToAccessExpiration === 0) {
            navigate('/');
            return;
        }

        if (authority) {
            if (authority === Authority.ADMIN) {
                if (!authState?.adminAuthority) {
                    navigate('/');
                    return;
                }
            }
            if (authority === Authority.MANAGER) {
                if (!authState?.adminAuthority && !authState?.managerAuthority) {
                    navigate('/');
                    return;
                }
            }
            if (authority === Authority.EMPLOYEE) {
                if (!authState?.adminAuthority && !authState?.managerAuthority && !authState?.employeeAuthority) {
                    navigate('/');
                    return;
                }
            }
            if (authority === Authority.CUSTOMER) {
                if (!authState?.adminAuthority && !authState?.managerAuthority && !authState?.employeeAuthority && !authState?.customerAuthority) {
                    navigate('/');
                    return;
                }
            }
        }
    }, [
        authority,
        navigate,
        authState?.adminAuthority,
        authState?.managerAuthority,
        authState?.employeeAuthority,
        authState?.customerAuthority
    ]);

    return (
        <>
            {children}
        </>
    )
}

export default AuthDefender;
