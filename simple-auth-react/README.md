# simple-auth-react

## generated part

To generate the final document you can use [bundle.sh](./bundle.sh) or call docker commands:

```shell
docker run --rm \
  -v ${PWD}:/local \
  openapitools/openapi-generator-cli generate \
  -i /local/simple-auth-api.yaml \
  -g typescript-fetch \
  -o /local/generated-client \
  -p fileNaming=kebab-case,supportsES6=true,withoutRuntimeChecks=true,withInterfaces=true,enumPropertyNaming=UPPERCASE

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
