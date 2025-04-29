# Stage 1: Build the application
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum first to leverage Docker cache
COPY ../go.mod go.sum ./
RUN go mod download

# Copy the rest of the application source code and build the binary
COPY .. .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /proxy main.go

# Stage 2: Create the final minimal image
FROM alpine:latest

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates && update-ca-certificates

# Create a non-root user
RUN addgroup -S proxygroup && adduser -S proxyuser -G proxygroup

# Copy the static binary from the builder stage
COPY --from=builder /proxy /app/proxy
RUN chmod +x /app/proxy

USER proxyuser

EXPOSE 8080

ENTRYPOINT ["/app/proxy"]

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD nc -z localhost 8080 || exit 1
