import { useContext } from 'react';
import { BrowserRouter } from 'react-router-dom';

import AppPage from './app/app-page';
import AccessExpiration from './component/layout/access-expiration.tsx';
import CookiesConsent from './component/layout/cookies-consent';
import ErrorInfo from './component/layout/error-info';
import WiwaSpinner from './component/ui/wiwa-spinner';
import { AppContext } from './context';

function App() {
    const appState = useContext(AppContext);

    return (
        <div className="min-h-screen flex flex-col text-sm xl:text-base">
            {appState?.up ?
                <BrowserRouter>
                    <ErrorInfo/>
                    <CookiesConsent/>
                    <AccessExpiration/>
                    <AppPage/>
                </BrowserRouter>
                :
                <div className="flex flex-grow items-center justify-center">
                    <div className="flex flex-col justify-center items-center gap-5">
                        <WiwaSpinner/>
                        <span>Connecting...</span>
                    </div>
                </div>
            }
        </div>
    )
}

export default App
