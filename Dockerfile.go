# Dockerfile for Go Speed Layer
# Builds probe_server, recon_server, and mcp_server

FROM golang:1.22-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make protobuf protobuf-dev

WORKDIR /build

# Copy Go module files
COPY go/go.mod go/go.sum ./
RUN go mod download

# Copy proto files and Go source
COPY proto/ ../proto/
COPY go/ ./

# Build gRPC servers
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /bin/probe_server ./cmd/probe_server
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /bin/recon_server ./cmd/recon_server
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /bin/mcp_server ./cmd/mcp_server

# Final stage - minimal runtime image
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates nmap curl

# Copy binaries from builder
COPY --from=builder /bin/probe_server /usr/local/bin/
COPY --from=builder /bin/recon_server /usr/local/bin/
COPY --from=builder /bin/mcp_server /usr/local/bin/

# Create non-root user
RUN addgroup -g 1000 llmrt && \
    adduser -D -u 1000 -G llmrt llmrt

USER llmrt

# Expose gRPC ports
EXPOSE 50051 50052 50053

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD nc -z localhost 50051 || exit 1

# Default command runs probe_server
# Override with docker-compose to run different servers
CMD ["probe_server"]
