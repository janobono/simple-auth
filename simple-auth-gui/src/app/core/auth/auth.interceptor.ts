// src/app/core/auth/auth.interceptor.ts
import {inject} from '@angular/core';
import {HttpErrorResponse, HttpInterceptorFn, HttpRequest} from '@angular/common/http';
import {catchError, switchMap, throwError} from 'rxjs';
import {LoginService} from './login.service';
import {TokenRefreshService} from './token-refresh.service';
import {SKIP_AUTH} from './auth.context';

function withBearer(req: HttpRequest<unknown>, token: string) {
  return req.clone({setHeaders: {Authorization: `Bearer ${token}`}});
}

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const loginService = inject(LoginService);
  const tokenRefreshService = inject(TokenRefreshService);

  if (!req.context.get(SKIP_AUTH)) {
    const token = loginService.getAccessToken();
    if (token) req = withBearer(req, token);
  }

  return next(req)
    .pipe(
      catchError((err: unknown) => {
        const httpErr = err as HttpErrorResponse;
        if (httpErr.status !== 401 || req.context.get(SKIP_AUTH)) {
          return throwError(() => httpErr);
        }

        return tokenRefreshService.getOrCreate(() => loginService.refresh()).pipe(
          switchMap((newToken) => next(withBearer(req, newToken))),
          // If refresh fails, clear tokens and return the ORIGINAL 401
          catchError(() => {
            loginService.clearTokens();
            return throwError(() => httpErr);
          })
        );
      })
    );
};
