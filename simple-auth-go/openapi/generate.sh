#!/bin/bash

docker run --rm -v ${PWD}:/local openapitools/openapi-generator-cli generate -router chi \
  -i /local/simple-auth-api.yaml \
  -g go-server \
  -o /local
