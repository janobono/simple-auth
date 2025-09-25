#!/bin/bash

docker run --rm -v ${PWD}:/local redocly/cli bundle \
  /local/spec/openapi.yaml \
  -o /local/simple-auth.yaml