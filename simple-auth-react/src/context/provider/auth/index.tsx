import { jwtDecode, JwtPayload } from 'jwt-decode';
import { ReactNode, useContext, useEffect, useState } from 'react';

import { AppContext, AuthContext } from '../../';
import { ClientResponse } from '../../../api/controller';
import * as authApi from '../../../api/controller/auth';
import {
    AuthenticationResponse,
    Authority,
    ChangeEmail,
    ChangePassword,
    ChangeUserDetails,
    Confirmation,
    ResetPassword,
    SignIn,
    SignUp,
    User
} from '../../../api/model/data';

const ACCESS_TOKEN = 'access-token';

export const REFRESH_TIMEOUT = 300000;

interface AuthData {
    accessToken: string,
    jwtPayload: JwtPayload,
    timeToAccessExpiration: number,
    user: User
}

const AuthProvider = ({children}: { children: ReactNode }) => {
    const appState = useContext(AppContext);

    const [busy, setBusy] = useState(false);
    const [authData, setAuthData] = useState<AuthData>();
    const [adminAuthority, setAdminAuthority] = useState(false);
    const [managerAuthority, setManagerAuthority] = useState(false);
    const [employeeAuthority, setEmployeeAuthority] = useState(false);
    const [customerAuthority, setCustomerAuthority] = useState(false);

    const [refreshCounter, setRefreshCounter] = useState(0);

    useEffect(() => {
        if (appState?.cookiesEnabled) {
            setAccessToken(localStorage.getItem(ACCESS_TOKEN) || undefined).then();
        }
    }, [appState?.cookiesEnabled]);

    useEffect(() => {
        if (authData?.jwtPayload) {
            const timeToAccessExpiration = getTimeToAccessExpiration(authData?.jwtPayload);
            if (timeToAccessExpiration > 0) {
                setAuthData(prevState => {
                    if (prevState === undefined) {
                        return undefined;
                    }
                    return {...prevState, timeToAccessExpiration};
                });
            } else {
                cleanState();
            }
        }

        const timer = setInterval(() => setRefreshCounter(refreshCounter + 1), REFRESH_TIMEOUT);
        return () => clearTimeout(timer);
    }, [refreshCounter]);

    useEffect(() => {
        setCustomerAuthority(hasAnyAuthority(authData, Authority.CUSTOMER));
        setEmployeeAuthority(hasAnyAuthority(authData, Authority.EMPLOYEE));
        setManagerAuthority(hasAnyAuthority(authData, Authority.MANAGER));
        setAdminAuthority(hasAnyAuthority(authData, Authority.ADMIN));
    }, [authData]);

    const setAccessToken = async (accessToken?: string) => {
        if (accessToken) {
            const jwtPayload = jwtDecode<JwtPayload>(accessToken);
            if (jwtPayload) {
                const timeToAccessExpiration = getTimeToAccessExpiration(jwtPayload);
                if (timeToAccessExpiration > 0) {
                    const response = await authApi.getUserDetail(accessToken);
                    if (response.data) {
                        setAuthData({
                            accessToken,
                            jwtPayload,
                            timeToAccessExpiration,
                            user: response.data
                        });
                        return;
                    }
                    if (response.error) {
                        console.log(response.error);
                    }
                }
            }
        }
        cleanState();
    }

    const cleanState = () => {
        localStorage.removeItem(ACCESS_TOKEN);
        setAuthData(undefined);
    }

    const getTimeToAccessExpiration = (jwtPayload?: JwtPayload) => {
        const result = jwtPayload ? (jwtPayload.exp || 0) * 1000 - Date.now() : 0;
        return result < 0 ? 0 : result;
    }

    const hasAnyAuthority = (authData: AuthData | undefined, ...authorities: string[]) => {
        if (authData?.jwtPayload?.aud && authData?.jwtPayload?.exp) {
            let hasAuthority;
            if (Array.isArray(authData.jwtPayload.aud)) {
                hasAuthority = authData.jwtPayload.aud.some(a => authorities.includes(a));
            } else {
                hasAuthority = authorities.some(a => a === authData.jwtPayload.aud);
            }
            return hasAuthority
                && (authData.user.confirmed || false)
                && (authData.user.enabled || false)
                && getTimeToAccessExpiration(authData.jwtPayload) > 0;
        }
        return false;
    }

    const handleAuthenticationResponse = (response: ClientResponse<AuthenticationResponse>) => {
        if (response.data) {
            if (appState?.cookiesEnabled) {
                localStorage.setItem(ACCESS_TOKEN, response.data.token || '');
            }
            setAccessToken(response.data.token).then();
        } else {
            cleanState();
        }
    }

    const signIn = async (signIn: SignIn) => {
        setBusy(true);
        try {
            const response = await authApi.signIn(signIn);
            handleAuthenticationResponse(response);
            return response;
        } finally {
            setBusy(false);
        }
    }

    const signOut = async () => {
        setBusy(true);
        try {
            cleanState();
        } finally {
            setBusy(false);
        }
    }

    const signUp = async (signUp: SignUp) => {
        setBusy(true);
        try {
            const response = await authApi.signUp(signUp);
            handleAuthenticationResponse(response);
            return response;
        } finally {
            setBusy(false);
        }
    }

    const confirm = async (confirmation: Confirmation) => {
        setBusy(true);
        try {
            const response = await authApi.confirm(confirmation);
            handleAuthenticationResponse(response);
            return response;
        } finally {
            setBusy(false);
        }
    }

    const resetPassword = async (resetPassword: ResetPassword) => {
        setBusy(true);
        try {
            return await authApi.resetPassword(resetPassword);
        } finally {
            setBusy(false);
        }
    }

    const changePassword = async (changePassword: ChangePassword) => {
        setBusy(true);
        try {
            const response = await authApi.changePassword(changePassword, authData?.accessToken);
            if (response.error === undefined) {
                handleAuthenticationResponse(response);
            }
            return response;
        } finally {
            setBusy(false);
        }
    }

    const changeEmail = async (changeEmail: ChangeEmail) => {
        setBusy(true);
        try {
            const response = await authApi.changeEmail(changeEmail, authData?.accessToken);
            if (response.error === undefined) {
                handleAuthenticationResponse(response);
            }
            return response;
        } finally {
            setBusy(false);
        }
    }

    const changeUserDetails = async (changeUserDetails: ChangeUserDetails) => {
        setBusy(true);
        try {
            const response = await authApi.changeUserDetails(changeUserDetails, authData?.accessToken);
            if (response.error === undefined) {
                handleAuthenticationResponse(response);
            }
            return response;
        } finally {
            setBusy(false);
        }
    }

    return (
        <AuthContext.Provider
            value={
                {
                    busy,
                    accessToken: authData?.accessToken,
                    user: authData?.user,
                    timeToAccessExpiration: authData?.timeToAccessExpiration || 0,
                    adminAuthority,
                    managerAuthority,
                    employeeAuthority,
                    customerAuthority,
                    signIn,
                    signOut,
                    signUp,
                    confirm,
                    resetPassword,
                    changePassword,
                    changeEmail,
                    changeUserDetails,
                    loadAccessToken: () => localStorage.getItem(ACCESS_TOKEN) || undefined
                }
            }
        >{children}
        </AuthContext.Provider>
    )
}

export default AuthProvider;
