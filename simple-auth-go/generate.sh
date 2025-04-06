#!/bin/bash

docker run --rm -v ${PWD}:/local openapitools/openapi-generator-cli generate \
  -i /local/porez-api.yaml \
  -g go-server \
  -o /local
