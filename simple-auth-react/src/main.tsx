import React from 'react';
import ReactDOM from 'react-dom/client';

import './index.css';

import App from './app';
import AppProvider from './context/provider/app';
import AuthProvider from './context/provider/auth';
import DialogProvider from './context/provider/dialog';
import ErrorProvider from './context/provider/error';

ReactDOM.createRoot(document.getElementById('root')!).render(
    <React.StrictMode>
        <ErrorProvider>
            <DialogProvider>
                <AppProvider>
                    <AuthProvider>
                        <App/>
                    </AuthProvider>
                </AppProvider>
            </DialogProvider>
        </ErrorProvider>
    </React.StrictMode>
)
