// src/app/core/auth/init.tokens.ts
import {inject} from '@angular/core';
import {LoginService} from './login.service';
import {CookieConsentService} from '../consent/cookie-consent.service';

export function initTokens(): void {
  const cookieConsentService = inject(CookieConsentService);
  const loginService = inject(LoginService);

  if (cookieConsentService.isCookiesEnabled()) {
    loginService.loadTokensFromStorage();
  }
}
