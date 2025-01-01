# open-api

- [OPENAPI Initiative](https://www.openapis.org/)
- [Redocly CLI](https://redocly.com/docs/cli)

## handwritten code part

Sometimes **YAML** documentation can be quite long so the best approach is split it into multiple smaller parts. All
these smaller components are located in [spec](./spec) directory. I want to mention that the **spec** directory
structure is based on **OPENAPI Initiative specification**.

## generated part

To generate the final document you can use [bundle.sh](./bundle.sh) or call docker command:

```shell
docker run --rm -v ${PWD}:/local redocly/cli bundle \
  /local/spec/openapi.yaml \
  -o /local/simple-auth-api.yaml
```

The result will be stored in [simple-auth-api.yaml](./simple-auth-api.yaml).
