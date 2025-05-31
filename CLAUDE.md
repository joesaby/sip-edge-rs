# CLAUDE.md - Project Development Guide

## Project Overview
sip-edge-rs is a high-performance SIP (Session Initiation Protocol) router implementation in Rust, designed specifically for cloud edge deployments. The project provides comprehensive security hardening and is optimized for production deployment in Kubernetes environments at the network edge.

## Key Commands

### Build & Test
```bash
# Build the project
cargo build --release

# Run all tests
cargo test

# Run security vulnerability tests specifically
cargo test --test vulnerability_tests

# Run benchmarks
cargo bench

# Run with debug logging
RUST_LOG=debug cargo run --release

# Run the test client example
cargo run --example test_client
```

### Code Quality
```bash
# Format code
cargo fmt

# Run linter
cargo clippy -- -D warnings

# Check for security vulnerabilities in dependencies
cargo audit
```

### Docker Operations
```bash
# Build Docker image
docker build -t sip-edge-rs:latest .

# Run container
docker run -d \
  -p 5060:5060/udp \
  -p 5060:5060/tcp \
  -p 5061:5061/tcp \
  --name sip-edge-rs \
  sip-edge-rs:latest
```

### Kubernetes Deployment
```bash
# Create namespace
kubectl create namespace sip-edge-rs

# Deploy
kubectl apply -f k8s-deployment.yaml

# Check status
kubectl get pods -n sip-edge-rs
kubectl logs -f deployment/sip-edge-rs -n sip-edge-rs
```

## Project Architecture

### Core Components
- **Parser** (`src/lib.rs`): RFC 3261 compliant SIP message parsing using nom
- **Security** (`src/security.rs`): Comprehensive vulnerability protection
- **Transport** (`src/transport.rs`): Async UDP/TCP/TLS transport layer
- **Codec** (`src/codec.rs`): Tokio codec for message framing
- **Router** (`src/main.rs`): Example router implementation
- **Utils** (`src/utils.rs`): Helper functions for SIP operations

### Security Features
The project protects against:
- SQL/Script/Command injection
- Buffer overflow attacks
- Header smuggling (CRLF injection)
- DoS attacks via rate limiting
- Response splitting
- Directory traversal
- Null byte injection
- Memory exhaustion
- Unicode attacks

### Performance Characteristics
- Benchmarked at >100k messages/second
- Sub-millisecond parsing latency
- Zero-copy parsing for efficiency
- Horizontal scaling support

## Development Guidelines

### Code Style
- Use `cargo fmt` before committing
- Address all `cargo clippy` warnings
- Follow Rust naming conventions
- Add documentation for public APIs

### Testing Strategy
1. Always run tests before commits
2. Add tests for new functionality
3. Run security tests for any security-related changes
4. Benchmark performance-critical changes

### Security Considerations
- Never log sensitive information (passwords, tokens)
- Validate all inputs strictly
- Use bounded allocations to prevent DoS
- Follow the principle of least privilege
- Keep dependencies updated

### Common Development Tasks

#### Adding a New SIP Method
1. Update the parser in `src/lib.rs` to recognize the method
2. Add validation rules in `src/security.rs` if needed
3. Update routing logic in `src/main.rs`
4. Add tests for the new method

#### Implementing Custom Security Rules
1. Create a new rule in `src/security.rs`
2. Implement the `SecurityRule` trait
3. Add the rule to the security validator
4. Write tests in `tests/vulnerability_tests.rs`

#### Performance Optimization
1. Run benchmarks before changes: `cargo bench -- --save-baseline before`
2. Make optimizations
3. Compare: `cargo bench -- --baseline before`
4. Profile if needed: `perf record --call-graph=dwarf ./target/release/sip-edge-rs`

## Troubleshooting

### High CPU Usage
- Check for routing loops
- Verify rate limiting configuration
- Review security rule complexity
- Enable CPU profiling

### Memory Issues
- Check for connection leaks
- Review message buffering
- Verify rate limiter cleanup
- Use memory profiling tools

### TLS Problems
- Verify certificate validity
- Check cipher suite compatibility
- Review TLS version requirements
- Enable TLS debugging: `RUST_LOG=rustls=debug`

### Parsing Failures
- Enable trace logging: `RUST_LOG=sip_parser=trace`
- Check for non-standard headers
- Verify Content-Length accuracy

## Environment Variables
- `SIP_TCP_ADDR`: TCP listen address (default: `0.0.0.0:5060`)
- `SIP_UDP_ADDR`: UDP listen address (default: `0.0.0.0:5060`)
- `SIP_TLS_ADDR`: TLS listen address (default: `0.0.0.0:5061`)
- `SIP_TLS_CERT`: Path to TLS certificate
- `SIP_TLS_KEY`: Path to TLS private key
- `RUST_LOG`: Log level (default: `info`)

## Important Files
- `src/lib.rs`: Core parser implementation
- `src/security.rs`: Security validation logic
- `tests/vulnerability_tests.rs`: Security test suite
- `benches/parser_benchmarks.rs`: Performance benchmarks
- `k8s-deployment.yaml`: Kubernetes manifests

## Quick Debugging
```bash
# Maximum verbosity
RUST_LOG=trace cargo run

# Specific module debugging
RUST_LOG=sip_parser::security=debug,sip_parser::codec=trace cargo run

# With timing information
RUST_LOG=debug RUST_LOG_SPAN_EVENTS=full cargo run
```

## Performance Metrics
- Simple request parsing: ~1μs
- Complex request with SDP: ~5μs
- Security validation: ~500ns
- Codec encode/decode: ~2μs

## Notes for Claude
- This is a security-critical network service - always prioritize security
- Performance is important but never at the cost of security
- The project uses async Rust with Tokio for concurrency
- All inputs must be validated and bounded
- Rate limiting is essential for DoS protection
- TLS configuration should use modern, secure defaults