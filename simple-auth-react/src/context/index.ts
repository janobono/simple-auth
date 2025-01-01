import { createContext } from 'react';

import { AppState } from './model/app';
import { AuthState } from './model/auth';
import { DialogState } from './model/dialog';
import { ErrorState } from './model/error';

export const AppContext = createContext<AppState | undefined>(undefined);
export const AuthContext = createContext<AuthState | undefined>(undefined);
export const DialogContext = createContext<DialogState | undefined>(undefined);
export const ErrorContext = createContext<ErrorState | undefined>(undefined);
