// src/app/core/auth/token-refresh.service.ts
import {Injectable} from '@angular/core';
import {Observable} from 'rxjs';
import {finalize, shareReplay} from 'rxjs/operators';

@Injectable({providedIn: 'root'})
export class TokenRefreshService {
  private refresh$?: Observable<string>;

  getOrCreate(start: () => Observable<string>): Observable<string> {
    if (!this.refresh$) {
      this.refresh$ = start().pipe(
        shareReplay(1),
        finalize(() => (this.refresh$ = undefined))
      );
    }
    return this.refresh$;
  }
}
