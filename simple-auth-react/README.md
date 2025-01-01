# simple-auth-react

## generated part

To generate the final document you can use [bundle.sh](./bundle.sh) or call docker commands:

```shell
docker run --rm -v ${PWD}:/local redocly/cli bundle \
  /local/spec/openapi.yaml \
  -o /local/simple-auth-api.yaml

cp ./generated-client/models/index.ts ../src/api/model/data.ts
```

## build

```shell
./build.sh
```

or

```shell
docker build -t porez-web:latest .
```
