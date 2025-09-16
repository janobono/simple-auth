// src/app/core/auth/login.service.ts
import { Injectable, effect, inject } from '@angular/core';
import { Observable, throwError } from 'rxjs';
import { map } from 'rxjs/operators';
import { HttpContext } from '@angular/common/http';

import { AuthControllerApi } from '../../api/services';
import { AuthenticationResponse, Refresh } from '../../api/models';
import { skipAuth } from './auth.context';
import { CookieConsentService } from '../consent/cookie-consent.service';

@Injectable({ providedIn: 'root' })
export class LoginService {
  private accessToken?: string;
  private refreshToken?: string;

  private readonly consent = inject(CookieConsentService);

  constructor(private authApi: AuthControllerApi) {
    // Keep localStorage in sync with consent
    effect(() => {
      if (this.consent.isCookiesEnabled()) {
        // Persist current tokens
        if (this.accessToken || this.refreshToken) {
          localStorage.setItem(
            'tokens',
            JSON.stringify({ access: this.accessToken, refresh: this.refreshToken })
          );
        }
      } else {
        // Remove from storage, but keep tokens in memory
        localStorage.removeItem('tokens');
      }
    });
  }

  setTokens(access: string | undefined, refresh?: string | undefined) {
    this.accessToken = access;
    this.refreshToken = refresh;

    if (this.consent.isCookiesEnabled()) {
      localStorage.setItem('tokens', JSON.stringify({ access, refresh }));
    }
  }

  clearTokens() {
    this.accessToken = undefined;
    this.refreshToken = undefined;
    localStorage.removeItem('tokens');
  }

  loadTokensFromStorage() {
    const raw = localStorage.getItem('tokens');
    if (raw) {
      try {
        const { access, refresh } = JSON.parse(raw);
        this.accessToken = access;
        this.refreshToken = refresh;
      } catch {
        this.clearTokens();
      }
    }
  }

  getAccessToken(): string | undefined {
    return this.accessToken;
  }

  getRefreshToken(): string | undefined {
    return this.refreshToken;
  }

  refresh(): Observable<string> {
    const rt = this.getRefreshToken();
    if (!rt) return throwError(() => new Error('No refresh token'));

    const body: Refresh = { refreshToken: rt };
    const context: HttpContext = skipAuth();

    return this.authApi.refresh({ body }, context).pipe(
      map((res: AuthenticationResponse) => {
        this.setTokens(res.accessToken, res.refreshToken);
        return res.accessToken ?? '';
      })
    );
  }
}
