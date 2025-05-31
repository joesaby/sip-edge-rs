# sip-edge-rs - High-Performance SIP Router for Cloud Edge

A production-ready, security-hardened SIP (Session Initiation Protocol) router implementation in Rust, designed for high-performance cloud edge deployments. Built specifically for Kubernetes environments, sip-edge-rs provides comprehensive protection against known SIP vulnerabilities while maintaining exceptional performance at the network edge.

## 🚀 Key Features

- **RFC 3261 Compliant**: Full SIP protocol support with all standard methods
- **Security Hardened**: Protection against all major SIP vulnerabilities
- **High Performance**: >100k messages/second, sub-millisecond latency
- **Modern Architecture**: Async Rust with Tokio, zero-copy parsing
- **Production Ready**: Docker containers, Kubernetes manifests, comprehensive monitoring
- **Well Tested**: Unit tests, security tests, benchmarks, and fuzzing

## 📋 Prerequisites

- Rust 1.75 or later
- Docker (for containerization)
- Kubernetes cluster (for deployment)
- Make (for convenience commands)

## 🏃 Quick Start

### Using Make (Recommended)

```bash
# Setup development environment
make setup

# Build and run
make build
make run

# Run tests
make test
make test-security

# Run with auto-reload during development
make dev

# See all available commands
make help
```

### Using Dev Container (VS Code)

1. Install [VS Code](https://code.visualstudio.com/) and [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
2. Open the project in VS Code
3. Click "Reopen in Container" when prompted
4. The development environment will be ready with all tools pre-installed

See [.devcontainer/README.md](.devcontainer/README.md) for detailed dev container documentation.

### Manual Setup

```bash
# Clone the repository
git clone https://github.com/your-org/sip-edge-rs.git
cd sip-edge-rs

# Build the project
cargo build --release

# Run tests
cargo test

# Run the router
RUST_LOG=info cargo run --release
```

## 📁 Project Structure

```
sip-edge-rs/
├── src/                         # Source code
│   ├── lib.rs                  # Core parser implementation
│   ├── codec.rs                # Tokio codec for message framing
│   ├── security.rs             # Security validation and protection
│   ├── transport.rs            # Network transport layer
│   ├── utils.rs                # Helper functions
│   └── main.rs                 # Example router implementation
├── tests/                       # Integration tests
│   └── vulnerability_tests.rs  # Security test suite
├── benches/                     # Performance benchmarks
│   └── parser_benchmarks.rs
├── examples/                    # Example applications
│   └── test_client.rs          # SIP test client
├── docs/                        # Documentation
│   └── arch.md                 # Architecture documentation
├── .devcontainer/               # VS Code dev container
│   ├── devcontainer.json       # Container configuration
│   ├── docker-compose.dev.yml  # Development services
│   └── sipp-scenarios/         # SIP test scenarios
├── Cargo.toml                   # Rust dependencies
├── Makefile                     # Development commands
├── Dockerfile                   # Production container
├── k8s-deployment.yaml         # Kubernetes manifests
└── CLAUDE.md                   # AI assistant context
```

## 🧪 Testing

### Running Tests

```bash
# All tests
make test

# Security vulnerability tests
make test-security

# Benchmarks
make bench

# Test coverage
make coverage

# Full test suite
make full-test
```

### SIP Protocol Testing

```bash
# Run SIPp load test
make sipp-test

# Manual SIPp testing
sipp -sf .devcontainer/sipp-scenarios/client.xml 127.0.0.1:5060 -m 1000 -r 50
```

## 🐳 Docker Deployment

```bash
# Build and run locally
make deploy-local

# Or manually:
docker build -t sip-edge-rs .
docker run -d \
  -p 5060:5060/udp \
  -p 5060:5060/tcp \
  -p 5061:5061/tcp \
  --name sip-edge-rs \
  sip-edge-rs

# Run with monitoring stack
make docker-monitor
```

## ☸️ Kubernetes Deployment

```bash
# Deploy to Kubernetes
make k8s-deploy

# Check status
make k8s-logs

# Port forward for testing
make k8s-port-forward
```

For detailed deployment instructions, see [docs/arch.md](docs/arch.md#deployment).

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SIP_TCP_ADDR` | TCP listen address | `0.0.0.0:5060` |
| `SIP_UDP_ADDR` | UDP listen address | `0.0.0.0:5060` |
| `SIP_TLS_ADDR` | TLS listen address | `0.0.0.0:5061` |
| `SIP_TLS_CERT` | Path to TLS certificate | `/etc/sip-edge-rs/certs/tls.crt` |
| `SIP_TLS_KEY` | Path to TLS private key | `/etc/sip-edge-rs/certs/tls.key` |
| `RUST_LOG` | Log level | `info` |

For security configuration options, see [docs/arch.md](docs/arch.md#security-configuration).

## 📊 Monitoring

The application exposes Prometheus metrics on port 9090:

- `sip_messages_total{method,transport}`: Total messages processed
- `sip_messages_errors_total{error_type}`: Parsing/validation errors  
- `sip_security_violations_total{violation_type}`: Security violations detected
- `sip_response_time_seconds`: Message processing latency histogram

For detailed monitoring setup, see [docs/arch.md](docs/arch.md#monitoring-and-observability).

## 🐛 Troubleshooting

For common issues and debugging tips, see [docs/arch.md](docs/arch.md#troubleshooting).

### Quick Debug Commands

```bash
# Enable debug logging
RUST_LOG=debug cargo run

# Trace specific module
RUST_LOG=sip_parser::security=trace cargo run

# Check for performance issues
make perf-test
```

## 📚 Documentation

- [Architecture Documentation](docs/arch.md) - Detailed architecture and implementation details
- [Dev Container Guide](.devcontainer/README.md) - VS Code development environment setup
- [API Documentation](https://docs.rs/sip-edge-rs) - Generated Rust API docs
- [CLAUDE.md](CLAUDE.md) - AI assistant context for development

## 🤝 Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests (`make ci`)
4. Commit your changes following [conventional commits](https://www.conventionalcommits.org/)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

### Development Setup

```bash
# Setup git hooks
make install-hooks

# Run CI checks before committing
make ci
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [Tokio](https://tokio.rs/) - Rust's async runtime
- Parsing powered by [nom](https://github.com/Geal/nom) - parser combinators
- TLS support via [rustls](https://github.com/rustls/rustls) - modern TLS implementation
- Inspired by [Kamailio](https://www.kamailio.org/) and [OpenSIPS](https://opensips.org/)

---

**Version**: 1.0.0  
**Last Updated**: January 2024  
**Maintainers**: Your Organization  
**Project**: sip-edge-rs - Rust SIP Router for Cloud Edge