# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /build

# Copy source directory
COPY src/ ./src/

# Build the application
WORKDIR /build/src
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o ../eth-watchtower .

# Final stage
FROM alpine:latest

WORKDIR /app

RUN apk --no-cache add ca-certificates && \
    adduser -D -g '' appuser

COPY --from=builder --chown=appuser:appuser /build/eth-watchtower .
COPY --chown=appuser:appuser config.json .

USER appuser
EXPOSE 2112

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget -q --spider http://localhost:2112/metrics || exit 1

ENTRYPOINT ["./eth-watchtower"]
CMD ["-config", "config.json"]