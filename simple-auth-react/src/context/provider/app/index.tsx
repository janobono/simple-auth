import { ReactNode, useEffect, useState } from 'react';

import { AppContext } from '../../';
import * as apiHealth from '../../../api/controller/health';

const COOKIES_ENABLED = 'cookies-enabled';
const HEALTH_TIMEOUT = 30000;

const AppProvider = ({children}: { children: ReactNode }) => {
    const [up, setUp] = useState(false);
    const [cookiesEnabled, setCookiesEnabled] = useState(false);

    const [actuatorCounter, setActuatorCounter] = useState(0);

    useEffect(() => {
        setCookiesEnabled(localStorage.getItem(COOKIES_ENABLED) === 'true');
    }, []);

    const enableCookies = () => {
        localStorage.setItem(COOKIES_ENABLED, 'true');
        setCookiesEnabled(true);
    }

    useEffect(() => {
        apiHealth.readyz().then(response => {
            if (response.data) {
                setUp(response.data.status === 'OK');
            } else {
                setUp(false);
            }
        });

        const timer = setInterval(() => setActuatorCounter(actuatorCounter + 1), HEALTH_TIMEOUT);
        return () => clearTimeout(timer);
    }, [actuatorCounter]);

    return (
        <AppContext.Provider
            value={
                {
                    up,
                    cookiesEnabled,
                    enableCookies
                }
            }
        >{children}
        </AppContext.Provider>
    )
}

export default AppProvider;
