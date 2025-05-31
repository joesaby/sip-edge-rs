# sip-edge-rs Development Makefile

.PHONY: help build test check fmt clippy audit bench clean docker k8s-deploy

# Default target
help: ## Show this help message
	@echo "sip-edge-rs Development Commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Development
build: ## Build the project
	cargo build

build-release: ## Build optimized release
	cargo build --release

test: ## Run all tests
	cargo test

test-verbose: ## Run tests with verbose output
	cargo test -- --nocapture

test-security: ## Run security vulnerability tests
	cargo test --test vulnerability_tests

check: ## Run cargo check
	cargo check

fmt: ## Format code
	cargo fmt

fmt-check: ## Check code formatting
	cargo fmt -- --check

clippy: ## Run clippy linter
	cargo clippy -- -D warnings

audit: ## Run security audit
	cargo audit

bench: ## Run benchmarks
	cargo bench

coverage: ## Generate test coverage report
	cargo tarpaulin --out Html

clean: ## Clean build artifacts
	cargo clean

# Development server
dev: ## Run development server with auto-reload
	cargo watch -x check -x test -x run

run: ## Run the SIP router
	cargo run

run-release: ## Run optimized release build
	cargo run --release

# Docker operations
docker-build: ## Build Docker image
	docker build -t sip-edge-rs .

docker-run: ## Run Docker container
	docker run -p 5060:5060/udp -p 5060:5060/tcp -p 5061:5061/tcp sip-edge-rs

docker-test: ## Run full docker-compose test stack
	cd .devcontainer && docker-compose -f docker-compose.dev.yml --profile testing up

docker-monitor: ## Run with monitoring stack
	cd .devcontainer && docker-compose -f docker-compose.dev.yml --profile monitoring up -d

docker-clean: ## Clean Docker containers and images
	cd .devcontainer && docker-compose -f docker-compose.dev.yml down -v
	docker system prune -f

# Kubernetes operations
k8s-deploy: ## Deploy to Kubernetes
	kubectl apply -f k8s-deployment.yaml

k8s-delete: ## Delete Kubernetes deployment
	kubectl delete -f k8s-deployment.yaml

k8s-logs: ## Show Kubernetes logs
	kubectl logs -f deployment/sip-edge-rs

k8s-port-forward: ## Port forward K8s service
	kubectl port-forward service/sip-edge-rs 5060:5060

# Testing with SIPp
sipp-install: ## Install SIPp (if not using devcontainer)
	@echo "Installing SIPp..."
	wget https://github.com/SIPp/sipp/releases/download/v3.7.2/sipp-3.7.2.tar.gz
	tar -xzf sipp-3.7.2.tar.gz
	cd sipp-3.7.2 && ./configure --enable-pcap && make -j$(nproc) && sudo make install
	rm -rf sipp-3.7.2*

sipp-test: ## Run SIPp load test against local server
	@echo "Starting SIP router..."
	cargo run &
	@echo "Waiting for server to start..."
	sleep 3
	@echo "Running SIPp test..."
	sipp -sf .devcontainer/sipp-scenarios/client.xml 127.0.0.1:5060 -m 100 -r 10
	@echo "Stopping server..."
	pkill -f "cargo run" || true

# Performance testing
perf-test: ## Run performance tests
	cargo build --release
	cargo bench
	@echo "Running memory usage test..."
	valgrind --tool=massif ./target/release/sip-edge-rs &
	sleep 5
	pkill -f sip-edge-rs || true

# Security testing
security-test: ## Run comprehensive security tests
	cargo audit
	cargo test --test vulnerability_tests
	@echo "Checking for unsafe code..."
	rg "unsafe" src/ || echo "No unsafe code found"

# Development setup
setup: ## Setup development environment (for local development)
	rustup component add clippy rustfmt
	rustup target add x86_64-unknown-linux-musl
	cargo install cargo-watch cargo-audit cargo-tarpaulin

# Git hooks
install-hooks: ## Install git pre-commit hooks
	@echo "Installing git hooks..."
	@echo '#!/bin/bash\ncargo fmt -- --check && cargo clippy -- -D warnings && cargo test' > .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "Git hooks installed!"

# Documentation
docs: ## Build and open documentation
	cargo doc --open

docs-deps: ## Document dependencies
	cargo tree

# All-in-one commands
ci: fmt-check clippy test audit ## Run CI checks (format, lint, test, audit)

full-test: clean build test bench coverage security-test ## Run comprehensive test suite

deploy-local: docker-build docker-run ## Build and run Docker container locally

.DEFAULT_GOAL := help 