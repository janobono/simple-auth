# simple-auth

Simple authentication and authorization service written in **Go**.

- [OpenAPI contract](./open-api/README.md)
- [License](./LICENSE)
- [SQL schema](./db/schema.sql) – Database schema

---

## 📦 Build

```bash
./build.sh
```

or

```bash
docker build -t simple-auth:latest .
```

---

## ⚙ Local Development

1. **Set environment variables**  
   Create a `.env` file or set them manually.

2. **Run dependencies**  
   Start required services (DB, Mail, etc.):
   ```bash
   docker compose -f infra.yaml up
   ```

3. **Run the service**
   ```bash
   go run .
   ```

---

## 🛠 Make Targets

If you have **`make`**, **Go** and **Node.js** installed, you can run:

| Target             | Description                                                              |
|--------------------|--------------------------------------------------------------------------|
| `tools`            | Install tools and modules                                                |
| `clean`            | Delete generated sources                                                 |
| `generate-openapi` | Generate REST API sources from OpenAPI into `generated/openapi`          |
| `generate-sqlc`    | Generate base db sql access methods and structures into `generated/sqlc` |
| `generate`         | Generate all sources                                                     |
| `build`            | Generate + build everything                                              |
| `fmt`              | Format code                                                              |
| `test`             | Run tests                                                                |
| `vet`              | Run `go vet` checks                                                      |

---

## 🌍 Environment Variables

### Server

| Name           | Example | Description                                            |
|----------------|---------|--------------------------------------------------------|
| `PROD`         | false   | Production mode flag (log level info instead of debug) |
| `HTTP_ADDRESS` | :8080   | HTTP port                                              |
| `CONTEXT_PATH` | /api    | REST API context path                                  |

### Database

| Name                 | Example             | Description              |
|----------------------|---------------------|--------------------------|
| `DB_URL`             | localhost:5432/app  | Database URL             |
| `DB_USER`            | app                 | DB username              |
| `DB_PASSWORD`        | app                 | DB password              |
| `DB_MAX_CONNECTIONS` | 5                   | Max DB connections       |
| `DB_MIN_CONNECTIONS` | 2                   | Min DB connections       |
| `DB_MIGRATIONS_URL`  | file://./migrations | Migrations directory URL |

### Mail

| Name                                    | Example                                | Description                                        |
|-----------------------------------------|----------------------------------------|----------------------------------------------------|
| `MAIL_HOST`                             | localhost                              | SMTP host                                          |
| `MAIL_PORT`                             | 1025                                   | SMTP port                                          |
| `MAIL_USER`                             | app@auth.org                           | SMTP username                                      |
| `MAIL_PASSWORD`                         | —                                      | SMTP password                                      |
| `MAIL_AUTH_ENABLED`                     | false                                  | Enable SMTP auth                                   |
| `MAIL_TLS_ENABLED`                      | false                                  | Enable TLS                                         |
| `MAIL_SIGN_UP_MAIL_SUBJECT`             | Sign Up Confirmation                   | Sign Up Confirmation mail subject                  |
| `MAIL_SIGN_UP_MAIL_TEMPLATE_URL`        | file://./templates/sign_up.html        | Sign Up mail template file URL                     |
| `MAIL_RESET_PASSWORD_MAIL_SUBJECT`      | Reset Password Confirmation            | Reset Password Confirmation mail subject           |
| `MAIL_RESET_PASSWORD_MAIL_TEMPLATE_URL` | file://./templates/reset_password.html | Reset Password Confirmation mail template file URL |

### Security & Auth

| Name                                    | Example                                                        | Description                           |
|-----------------------------------------|----------------------------------------------------------------|---------------------------------------|
| `SECURITY_READ_AUTHORITIES`             | manager,employee                                               | Default read roles                    |
| `SECURITY_WRITE_AUTHORITIES`            | admin                                                          | Default write roles                   |
| `SECURITY_DEFAULT_USERNAME`             | simple@auth.org                                                | Default admin email (simple@auth.org) |
| `SECURITY_DEFAULT_PASSWORD`             | `$2a$10$gRKMsjTON2A4b5PDIgjej.EZPvzVaKRj52Mug/9bfQBzAYmVF0Cae` | Default admin password hash (simple)  |
| `SECURITY_TOKEN_ISSUER`                 | simple                                                         | JWT issuer                            |
| `SECURITY_ACCESS_TOKEN_EXPIRES_IN`      | 30                                                             | Access token expiry (minutes)         |
| `SECURITY_ACCESS_TOKEN_JWK_EXPIRES_IN`  | 720                                                            | Access token JWK expiry (minutes)     |
| `SECURITY_REFRESH_TOKEN_EXPIRES_IN`     | 10080                                                          | Refresh token expiry (minutes)        |
| `SECURITY_REFRESH_TOKEN_JWK_EXPIRES_IN` | 20160                                                          | Refresh token JWK expiry (minutes)    |
| `SECURITY_CONTENT_TOKEN_EXPIRES_IN`     | 10080                                                          | Content token expiry (minutes)        |
| `SECURITY_CONTENT_TOKEN_JWK_EXPIRES_IN` | 20160                                                          | Content token JWK expiry (minutes)    |

### Captcha

| Name                 | Example                                     | Description                           |
|----------------------|---------------------------------------------|---------------------------------------|
| CAPTCHA_CHARACTERS   | abcdefghijklmnopqrstuvwxyz0123456789        | Characters used in captcha            |
| CAPTCHA_TEXT_LENGTH  | 8                                           | Captcha text length                   |
| CAPTCHA_IMAGE_WIDTH  | 200                                         | Captcha image width                   |
| CAPTCHA_IMAGE_HEIGHT | 70                                          | Captcha image height                  |
| CAPTCHA_NOISE_LINES  | 8                                           | Number of noise lines in the captcha  |
| CAPTCHA_FONT         | /usr/share/fonts/dejavu/DejaVuSans-Bold.ttf | Font path used for captcha generation |
| CAPTCHA_FONT_SIZE    | 32                                          | Font size for captcha                 |

### CORS

| Name                     | Example                                  | Description                     |
|--------------------------|------------------------------------------|---------------------------------|
| `CORS_ALLOWED_ORIGINS`   | http://localhost:3000                    | Allowed origins                 |
| `CORS_ALLOWED_METHODS`   | GET,POST,PUT,PATCH,DELETE                | Allowed HTTP methods            |
| `CORS_ALLOWED_HEADERS`   | Origin,Content-Type,Accept,Authorization | Allowed headers                 |
| `CORS_EXPOSED_HEADERS`   | Content-length                           | Exposed headers                 |
| `CORS_ALLOW_CREDENTIALS` | true                                     | Allow credentials               |
| `CORS_MAX_AGE`           | 12                                       | Preflight cache max age (hours) |

### Application

| Name                             | Example                                  | Description                                 |
|----------------------------------|------------------------------------------|---------------------------------------------|
| `APP_CONFIRMATION_WEB_URL`       | http://localhost:3000                    | Confirmation web URL                        |
| `APP_CONFIRMATION_PATH`          | /confirm?token=                          | Confirmation path                           |
| `APP_SIGN_UP_MAIL_CONFIRMATION`  | true                                     | Sign up mail confirmation enabled/disabled  |
| `APP_PASSWORD_CHARACTERS`        | abcdefghijklmnopqrstuvwxyz0123456789     | Allowed password characters                 |
| `APP_PASSWORD_LENGTH`            | 8                                        | Generated password length                   |
| `APP_MANDATORY_USER_ATTRIBUTES`  | first_name=Fist Name,last_name=Last Name | Key=Value pairs of required user attributes |
| `APP_MANDATORY_USER_AUTHORITIES` | visitor                                  | Required authorities for new users          |

---

## ⚠ Security Warning

**Default credentials (REMOVE in production):**

```
Email: simple@auth.org
Password hash: $2a$10$gRKMsjTON2A4b5PDIgjej.EZPvzVaKRj52Mug/9bfQBzAYmVF0Cae
```

Leaving these active in production is a serious security risk.
