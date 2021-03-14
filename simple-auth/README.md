# simple-auth

Run simple auth locally with docker-compose.

## endpoints

- [traefik](http://127.0.0.1:8080/)
- [frontend](http://127.0.0.1/)
- [backend health check](http://127.0.0.1/api/health)

## run

```
docker-compose up
```

## stop

```
docker-compose down
```

## test user

|attribute|value|
|---|---|
|username|trevor.ochmonek.dev|
|password|MelmacAlf+456|
|email|trevor.ochmonek@melmac.com|
|given_name|Trevor|
|family_name|Ochmonek|
|hotel_code|simple-123|

### import test user

- [test_user.sql](test_user.sql)

```
docker cp ./test_user.sql simple-auth_db_1:/test_user.sql
docker exec -it simple-auth_db_1 bash
psql "dbname='app' user='app' password='app' host='localhost'" -f /test_user.sql
```

### authenticate

```
curl --header "Content-Type: application/json" \
--request POST \
--data '{"username":"trevor.ochmonek.dev","password":"MelmacAlf+456"}' \
http://localhost/api/authenticate
```

### current-user

```
curl -H "Authorization: Bearer REPLACE_ME_WITH_TOKEN" http://localhost/api/current-user
```

```json
{
  "id": 1,
  "username": "trevor.ochmonek.dev",
  "password": null,
  "enabled": true,
  "authorities": [
    {
      "id": 1,
      "name": "view-users"
    },
    {
      "id": 2,
      "name": "manage-users"
    },
    {
      "id": 3,
      "name": "view-hotels"
    },
    {
      "id": 4,
      "name": "manage-hotels"
    }
  ],
  "attributes": {
    "hotel_code": "simple-123",
    "given_name": "Trevor",
    "family_name": "Ochmonek",
    "email": "trevor.ochmonek@melmac.com"
  }
}
```
