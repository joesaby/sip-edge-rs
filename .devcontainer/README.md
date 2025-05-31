# sip-edge-rs Development Container

This directory contains the VS Code development container configuration for the sip-edge-rs project.

## Quick Start

1. Install [VS Code](https://code.visualstudio.com/) and the [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
2. Open the project in VS Code
3. Click "Reopen in Container" when prompted (or press `F1` and select "Dev Containers: Reopen in Container")
4. Wait for the container to build (~5-10 minutes on first run)

## What's Included

### Development Tools
- Rust 1.75+ with cargo, clippy, rustfmt
- Additional cargo tools: watch, edit, tree, audit, tarpaulin
- sccache for faster rebuilds
- Cross-compilation support (x86_64-unknown-linux-musl)

### SIP Testing Tools
- SIPp for protocol testing and load generation
- Pre-configured test scenarios in `sipp-scenarios/`
- TLS certificates for testing in `certs/`

### Container & Kubernetes
- Docker-in-Docker support
- kubectl, helm, and minikube
- docker-compose for multi-service testing

### Debugging & Analysis
- Network tools: tcpdump, tshark, netcat, iperf3
- Performance tools: perf, valgrind
- Code coverage and security auditing

## Container Configuration

### devcontainer.json
- Base image: Rust on Debian
- Automatic port forwarding for SIP ports (5060, 5061)
- VS Code extensions for Rust development
- Post-creation setup script

### docker-compose.dev.yml
Provides additional services for testing:
- SIPp server for testing
- Prometheus for metrics collection
- Grafana for visualization
- Multiple testing profiles

### Pre-configured Aliases

The container includes helpful command aliases:
- `cr`, `cb`, `ct`, `cc` - Cargo shortcuts
- `cw` - Cargo watch for auto-rebuild
- `sipp-client`, `sipp-server` - Quick SIP testing
- `siplog` - Monitor SIP traffic
- See full list in `.devcontainer/setup.sh`

## Usage Examples

### Running Tests
```bash
# All tests with coverage
make full-test

# Quick test with auto-reload
cw
```

### SIP Protocol Testing
```bash
# Start the router
cargo run

# In another terminal, run load test
sipp-client 127.0.0.1
```

### Multi-Service Testing
```bash
# Start full stack with monitoring
docker-compose -f docker-compose.dev.yml --profile monitoring up
```

## Troubleshooting

- **Build failures**: Try rebuilding the container from VS Code
- **Port conflicts**: Check that ports 5060-5061 are available
- **Performance**: Ensure Docker has sufficient resources allocated

For more details about the development workflow, see the main [README.md](../README.md).