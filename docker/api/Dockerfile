# Multi-stage build for api:
# Stage 1: Build environment
FROM golang:1.21-alpine AS builder
RUN apk add --no-cache git gcc musl-dev
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o api cmd/api/main.go

# Stage 2: Runtime environment
FROM alpine:3.18
RUN apk add --no-cache ca-certificates
RUN addgroup -g 1000 api && adduser -u 1000 -G api -s /bin/sh -D api
WORKDIR /app
COPY --from=builder /build/api .
COPY --from=builder /build/configs ./configs
RUN chown -R api:api /app
USER api
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/app/api", "health"]
ENTRYPOINT ["/app/api"]
