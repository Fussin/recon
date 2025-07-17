# Multi-stage build for scanner:
# Stage 1: Build environment
FROM golang:1.21-alpine AS builder
RUN apk add --no-cache git gcc musl-dev
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o scanner cmd/scanner/main.go

# Stage 2: Runtime environment
FROM alpine:3.18
RUN apk add --no-cache ca-certificates chromium chromium-chromedriver
RUN addgroup -g 1000 scanner && adduser -u 1000 -G scanner -s /bin/sh -D scanner
WORKDIR /app
COPY --from=builder /build/scanner .
COPY --from=builder /build/configs ./configs
RUN chown -R scanner:scanner /app
USER scanner
EXPOSE 8080 9090
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/app/scanner", "health"]
ENTRYPOINT ["/app/scanner"]
