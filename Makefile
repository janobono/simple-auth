.PHONY: tools clean generate generate-openapi generate-sqlc build fmt test vet

default: build

tools:
	@echo "  >  Installing openapi generator"
	@npm install @openapitools/openapi-generator-cli -g
	@echo "  >  Installing sqlc"
	@go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest

clean:
	@echo "  >  Cleaning build cache"
	@go clean ./...
	@rm -rf bin
	@rm -rf generated

generate-openapi:
	@echo "  > Generate openapi source files"
	mkdir -p generated &&\
	openapi-generator-cli generate \
	--generator-name go-gin-server \
	--input-spec open-api/simple-auth.yaml \
	--output generated/openapi-gen \
	--additional-properties=interfaceOnly=true,packageName=openapi,generateMetadata=false,generateGoMod=false &&\
	mkdir -p generated/openapi &&\
	cp -r generated/openapi-gen/go/* generated/openapi/ &&\
	rm -rf generated/openapi-gen

generate-sqlc:
	@echo "  >  Generate sqlc files"
	sqlc generate -f db/sqlc.yaml

generate: generate-openapi generate-sqlc

build: generate
	go build -o bin/simple-auth ./cmd/main.go

fmt:
	@echo "  >  Formatting code"
	@go fmt ./...

test:
	@echo "  >  Executing unit tests"
	@go test -v ./...

vet:
	@echo "  >  Checking code with vet"
	@go vet ./...
