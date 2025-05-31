# Multi-stage Dockerfile for sip-edge-rs - High-performance SIP Router for Cloud Edge

# Build stage
FROM rust:1.75-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev openssl-dev pkgconfig

# Create app directory
WORKDIR /usr/src/sip-edge-rs

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src
COPY benches ./benches
COPY tests ./tests

# Build release binary with optimizations
RUN cargo build --release --locked

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    openssl \
    libgcc \
    tini

# Create non-root user
RUN addgroup -g 1000 sip && \
    adduser -D -s /bin/sh -u 1000 -G sip sip

# Copy binary from builder
COPY --from=builder /usr/src/sip-edge-rs/target/release/sip-edge-rs /usr/local/bin/sip-edge-rs

# Create directories for TLS certificates
RUN mkdir -p /etc/sip-edge-rs/certs && \
    chown -R sip:sip /etc/sip-edge-rs

# Set security options
USER sip

# Expose SIP ports
# 5060: SIP UDP/TCP
# 5061: SIP TLS
EXPOSE 5060/udp 5060/tcp 5061/tcp

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD nc -z localhost 5060 || exit 1

# Use tini as init system to handle signals properly
ENTRYPOINT ["/sbin/tini", "--"]

# Default command
CMD ["sip-edge-rs"]

# Labels for Kubernetes
LABEL maintainer="your-email@example.com" \
      version="1.0.0" \
      description="High-performance Rust SIP Router for Cloud Edge with TLS support" \
      org.opencontainers.image.source="https://github.com/your-org/sip-edge-rs" \
      org.opencontainers.image.vendor="Your Organization" \
      org.opencontainers.image.licenses="MIT"