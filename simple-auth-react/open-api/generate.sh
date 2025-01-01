#!/bin/bash

docker run --rm \
  -v ${PWD}:/local \
  openapitools/openapi-generator-cli generate \
  -i /local/simple-auth-api.yaml \
  -g typescript-fetch \
  -o /local/generated-client \
  -p fileNaming=kebab-case,supportsES6=true,withoutRuntimeChecks=true,withInterfaces=true,enumPropertyNaming=UPPERCASE

cp ./generated-client/models/index.ts ../src/api/model/data.ts
