# simple auth spring

## build

To build the service you can use [build.sh](./build.sh) or call docker command:

```shell
docker build -t simple-auth-spring:latest .
```

## generated part

To generate sources you can call maven command:

```shell
mvn clean generate-sources
```

Generated result will be stored in **./target/generated-sources/openapi**

## environment variables

| Name                               | Default                              |
|------------------------------------|--------------------------------------|
| PORT                               | 8080                                 |
| CONTEXT_PATH                       | /api                                 |
| LOG_LEVEL                          | debug                                |
| DB_URL                             | jdbc:postgresql://localhost:5432/app |
| DB_USER                            | app                                  |
| DB_PASS                            | app                                  |
| DB_POOL_SIZE                       | 5                                    |
| DB_POOL_IDLE                       | 2                                    |
| MAIL_HOST                          | localhost                            |
| MAIL_PORT                          | 1025                                 |
| MAIL_USER                          |                                      |
| MAIL_PASS                          |                                      |
| MAIL_AUTH                          | false                                |
| MAIL_TLS_ENABLE                    | false                                |
| CAPTCHA_LENGTH                     | 4                                    |
| CONFIRM_PATH                       | /confirm/                            |
| MAIL                               | simple@auth.org                      |
| WEB_URL                            | http://localhost:8080                |
| SIGN_UP_TOKEN_EXPIRES_IN           | 1440 (min)                           |
| RESET_PASSWORD_TOKEN_EXPIRES_IN    | 1440 (min)                           |
| TOKEN_ISSUER                       | simple                               |
| TOKEN_EXPIRES_IN                   | 120 (min)                            |
| SECURITY_PUBLIC_PATH_PATTERN_REGEX | *                                    |
| VERIFICATION_TOKEN_ISSUER          | simple-verification                  |
| CORS_ALLOWED_ORIGINS               | http://localhost:5173                |
| CORS_ALLOWED_METHODS               | GET,POST,PUT,OPTIONS,PATCH,DELETE    |
| CORS_ALLOWED_HEADERS               | Authorization,Content-Type           |
| CORS_ALLOW_CREDENTIALS             | true                                 |

(*) - ^(/livez|/readyz|/captcha|/auth/(confirm|reset-password|sign-in|sign-up))$
