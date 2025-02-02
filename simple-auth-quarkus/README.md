# simple-auth-quarkus

## build

To build the service you can use [build.sh](./build.sh) or call docker command:

```shell
docker build -t simple-auth-quarkus:latest .
```

## generated part

To generate sources you can call maven command:

```shell
mvn clean generate-sources
```

Generated result will be stored in **./target/generated-sources/openapi**

## environment variables

## environment variables

| Name                               | Default                           |
|------------------------------------|-----------------------------------|
| PORT                               | 8080                              |
| CONTEXT_PATH                       | /api                              |
| LOG_LEVEL                          | DEBUG                             |
| QUARKUS_MAILER_HOST                |                                   |
| QUARKUS_MAILER_PORT                |                                   |
| QUARKUS_MAILER_USERNAME            |                                   |
| QUARKUS_MAILER_PASSWORD            |                                   |
| QUARKUS_DATASOURCE_DB_KIND         |                                   |
| QUARKUS_DATASOURCE_USERNAME        |                                   |
| QUARKUS_DATASOURCE_PASSWORD        |                                   |
| QUARKUS_DATASOURCE_JDBC_URL        |                                   |
| CAPTCHA_LENGTH                     | 4                                 |
| CONFIRM_PATH                       | /confirm/                         |
| MAIL                               | simple@auth.org                   |
| WEB_URL                            | http://localhost:8080             |
| SIGN_UP_TOKEN_EXPIRES_IN           | 1440 (min)                        |
| RESET_PASSWORD_TOKEN_EXPIRES_IN    | 1440 (min)                        |
| TOKEN_ISSUER                       | simple                            |
| TOKEN_EXPIRES_IN                   | 120 (min)                         |
| SECURITY_PUBLIC_PATH_PATTERN_REGEX | *                                 |
| VERIFICATION_TOKEN_ISSUER          | simple-verification               |
| CORS_ALLOWED_ORIGINS               | http://localhost:5173             |
| CORS_ALLOWED_METHODS               | GET,POST,PUT,OPTIONS,PATCH,DELETE |
| CORS_ALLOWED_HEADERS               | Authorization,Content-Type        |
| CORS_ALLOW_CREDENTIALS             | true                              |
| CORS_EXPOSED_HEADERS               | Authorization                     |

(*) - ^(/livez|/readyz|/captcha|/auth/(confirm|reset-password|sign-in|sign-up))$