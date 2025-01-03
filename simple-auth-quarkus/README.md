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
