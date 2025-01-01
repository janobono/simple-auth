import { useContext, useEffect, useState } from 'react';

import { AppContext } from '../../context';

const CookiesConsent = () => {
    const appState = useContext(AppContext);

    const [show, setShow] = useState(false);

    useEffect(() => {
        if (appState === undefined) {
            setShow(false);
        } else if (appState.cookiesEnabled === undefined || appState.cookiesEnabled) {
            setShow(false);
        } else {
            setShow(true);
        }
    }, [appState]);

    return (!show ? null :
            <div className="alert alert-warning text-xs xl:text-sm">
                <span>We use cookies to optimize the site's functionality.</span>
                <button
                    className="btn btn-sm normal-case text-xs xl:text-sm"
                    onClick={() => {
                        appState?.enableCookies();
                    }}
                >Enable cookies
                </button>
            </div>
    )
}

export default CookiesConsent;
