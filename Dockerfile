# Stage1: OpenAPI code generation
FROM public.ecr.aws/docker/library/node:lts-alpine AS openapi

RUN apk add openjdk17-jre && npm install @openapitools/openapi-generator-cli -g

RUN apk add --no-cache ttf-dejavu

WORKDIR /src
COPY open-api/simple-auth.yaml open-api/simple-auth.yaml

RUN openapi-generator-cli generate \
    --generator-name go-gin-server \
    --input-spec open-api/simple-auth.yaml \
    --output generated/openapi-gen \
    --additional-properties=interfaceOnly=true,packageName=openapi,generateMetadata=false,generateGoMod=false &&\
    mkdir -p generated/openapi && cp -r generated/openapi-gen/go/* generated/openapi/ && rm -rf generated/openapi-gen

# Stage2: sqlc code generation
FROM public.ecr.aws/docker/library/golang:alpine AS sqlc

RUN go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest

WORKDIR /src
COPY db db/

RUN mkdir -p generated/sqlc && sqlc generate -f db/sqlc.yaml

# Stage3: build
FROM public.ecr.aws/docker/library/golang:alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
COPY --from=openapi /src/generated/openapi ./generated/openapi
COPY --from=sqlc /src/generated/sqlc ./generated/sqlc

RUN CGO_ENABLED=0 GOOS=linux go build -o bin/simple-auth ./cmd/main.go

# Stage4: Final image
FROM gcr.io/distroless/static:nonroot

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/bin/simple-auth .
COPY migrations /app/migrations
COPY templates /app/templates
COPY --from=openapi /usr/share/fonts/dejavu/DejaVuSans-Bold.ttf /usr/share/fonts/dejavu/DejaVuSans-Bold.ttf

# Default command
ENTRYPOINT ["/app/simple-auth"]