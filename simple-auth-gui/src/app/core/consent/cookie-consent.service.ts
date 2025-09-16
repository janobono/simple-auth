// src/app/core/auth/cookie-consent.service.ts
import {computed, effect, inject, Injectable, PLATFORM_ID, signal} from '@angular/core';
import {isPlatformBrowser} from '@angular/common';

const KEY = 'cookiesEnabled';

@Injectable({providedIn: 'root'})
export class CookieConsentService {
  private readonly platformId = inject(PLATFORM_ID);
  private readonly isBrowser = isPlatformBrowser(this.platformId);

  private readonly cookiesEnabled = signal<boolean>(false);

  readonly isCookiesEnabled = computed(() => this.cookiesEnabled());

  constructor() {
    if (this.isBrowser) {
      const raw = localStorage.getItem(KEY);
      this.cookiesEnabled.set(raw === 'true');
    }

    // Persist changes
    effect(() => {
      if (!this.isBrowser) return;
      if (this.cookiesEnabled()) {
        localStorage.setItem(KEY, 'true');
      } else {
        localStorage.removeItem(KEY);
      }
    });

    // Cross-tab sync
    if (this.isBrowser) {
      window.addEventListener('storage', (e) => {
        if (e.key === KEY) {
          const next = e.newValue === 'true';
          if (this.cookiesEnabled() !== next) {
            this.cookiesEnabled.set(next);
          }
        }
      });
    }
  }

  setEnabled(enabled: boolean) {
    this.cookiesEnabled.set(enabled);
  }
}
