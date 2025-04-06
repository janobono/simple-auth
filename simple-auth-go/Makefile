default: build

clean:
	@echo "  >  Cleaning build cache"
	@-rm -rf bin && go clean ./...

build:
	@echo "  >  Building binary"
	@go build -o bin/simple-auth cmd/main.go

run: build
	@echo "  >  Running binary"
	@./bin/simple-auth

fmt:
	@echo "  >  Formatting code"
	@go fmt ./...

test:
	@echo "  >  Executing unit tests"
	@go test -v -timeout 60s -race ./...

vet:
	@echo "  >  Checking code with vet"
	@go vet ./...
