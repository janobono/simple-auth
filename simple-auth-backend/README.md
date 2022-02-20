# simple auth backend

Simple authentication backend, roles and users management api.

## build

```
docker build -t sk.janobono/simple-auth-backend .
```

## environment variables

| Name                | Default value                        |
|---------------------|--------------------------------------|
| PORT                | 8080                                 | 
| CONTEXT_PATH        | /api/backend                         |
| LOG_LEVEL           | debug                                | 
| DB_URL              | jdbc:postgresql://localhost:5432/app |  
| DB_USER             | app                                  | 
| DB_PASS             | app                                  | 
| APP_ISSUER          | simple-auth                          | 
| APP_JWT_EXPIRATION  | 7200                                 |
| APP_JWT_PRIVATE_KEY | *                                    | 
| APP_JWT_PUBLIC_KEY  | **                                   | 

- *, ** - generated with `sk.janobono.KeyGenerator`

## endpoints

Documentation is generated in [OpenApi](https://www.openapis.org/) 3.0 format, you should find it in
`./target/api-docs.yml` after build. You should use [swagger editor](https://editor.swagger.io/) to preview api.

### POST /api/backend/authenticate

```
curl --header "Content-Type: application/json" \
--request POST \
--data '{"username":"trevor.ochmonek.dev","password":"MelmacAlf+456"}' \
http://localhost/api/backend/authenticate
```

result:

```json
{
  "bearer": "eyJ..."
}
```
