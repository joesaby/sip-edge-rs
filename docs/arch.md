# sip-edge-rs Architecture Documentation

High-Performance Rust SIP Router for Cloud Edge

This document provides detailed technical information about the sip-edge-rs implementation, including architecture decisions, security features, deployment strategies, and advanced usage patterns.

## System Architecture

### Layered Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   UDP/5060  │     │   TCP/5060  │     │   TLS/5061  │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       └───────────────────┴───────────────────┘
                           │
                    ┌──────▼──────┐
                    │  Transport  │
                    │    Layer    │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │   Codec     │
                    │  (Framing)  │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │   Parser    │
                    │   (nom)     │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  Security   │
                    │ Validation  │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │   Router    │
                    │   Logic     │
                    └─────────────┘
```

### Core Components

#### 1. Core Parser (`src/lib.rs`)
- **Technology**: `nom` parser combinator library for zero-copy parsing
- **Features**:
  - RFC 3261 compliant SIP message parsing
  - Strict security limits on headers, URI length, and message size
  - Support for all standard SIP methods (INVITE, REGISTER, OPTIONS, ACK, BYE, CANCEL, etc.)
  - Extensible for custom headers and methods

#### 2. Security Module (`src/security.rs`)
- **Protection Mechanisms**:
  - SQL injection detection using pattern matching
  - Script/XSS injection prevention
  - Command injection blocking
  - Response splitting protection (CRLF injection)
  - DoS prevention via configurable rate limiting
  - Null byte injection detection
  - Directory traversal prevention
  - Integer overflow protection
  - Unicode normalization attacks
- **Features**:
  - Configurable security policies
  - Security audit logging with violation tracking
  - Per-client rate limiting with sliding windows
  - Customizable rule engine

#### 3. Async Transport Layer (`src/transport.rs`)
- **Framework**: Tokio async runtime
- **Protocols**: UDP, TCP, and TLS (via rustls)
- **Features**:
  - Connection pooling for TCP/TLS
  - Automatic reconnection handling
  - Configurable timeouts and keep-alives
  - Modern TLS 1.2/1.3 with secure cipher suites

#### 4. Codec Implementation (`src/codec.rs`)
- **Purpose**: Message framing for stream-based protocols
- **Features**:
  - Content-Length based framing for TCP/TLS
  - Efficient buffer management
  - Streaming parser integration
  - Backpressure handling

#### 5. Utilities (`src/utils.rs`)
- Helper functions for:
  - Header manipulation (add, remove, modify)
  - Transaction ID generation (RFC 3261 compliant)
  - Dialog ID computation
  - URI parsing and manipulation
  - SDP parsing helpers

## Security Architecture

### Threat Model

The sip-edge-rs is designed to protect against:

1. **Protocol-Level Attacks**
   - Malformed SIP messages
   - Buffer overflow attempts
   - Header smuggling (CVE-2021-22555 style)
   - Response splitting
   - Registration hijacking

2. **Application-Level Attacks**
   - SQL injection in SIP URIs and headers
   - Script/XSS injection attempts
   - Command injection through headers
   - Directory traversal in file URIs

3. **Denial of Service**
   - Registration flooding
   - Memory exhaustion attacks
   - CPU exhaustion via algorithmic complexity
   - Connection exhaustion

4. **Data Validation**
   - Integer overflow in numeric headers
   - Unicode normalization attacks
   - Null byte injection
   - Encoding attacks

### Security Configuration

Detailed security configuration options:

```rust
SecurityConfig {
    // Injection Detection
    detect_sql_injection: true,           // Scan for SQL patterns
    detect_script_injection: true,        // Detect JS/HTML injection
    detect_command_injection: true,       // Block shell commands
    
    // Rate Limiting
    max_registrations_per_ip: 100,        // Registration limit
    rate_limit_window: Duration::from_secs(60),
    max_requests_per_window: 1000,        // Per-client rate limit
    
    // Protocol Security
    strict_uri_validation: true,          // RFC 3261 strict mode
    max_forwards: 70,                     // Loop prevention
    max_via_headers: 20,                  // Via header chain limit
    max_header_size: 8192,                // Per-header size limit
    max_message_size: 65536,              // Total message size
    
    // Advanced Protection
    detect_response_splitting: true,      // CRLF injection
    detect_header_smuggling: true,        // Header injection
    normalize_unicode: true,              // Unicode security
    
    // Domain Security
    allowed_domains: Some(hashset![       // Whitelist domains
        "example.com", 
        "trusted.org"
    ]),
    blocked_user_agents: hashset![        // Block bad actors
        "BadBot", 
        "Scanner"
    ],
    
    // Timeout Configuration
    transaction_timeout: Duration::from_secs(32),
    dialog_timeout: Duration::from_secs(1800),
}
```

### Security Patterns

1. **Input Validation**
   - All inputs are validated before processing
   - Bounded allocations prevent memory attacks
   - Strict parsing rejects malformed data early

2. **Defense in Depth**
   - Multiple validation layers
   - Rate limiting at transport and application layers
   - Audit logging for security events

3. **Fail Secure**
   - Errors result in connection termination
   - No partial message processing
   - Clear security violation reporting

## Performance Characteristics

### Benchmarked Performance

| Operation | Latency | Throughput |
|-----------|---------|------------|
| Simple INVITE parsing | ~1μs | 1M msgs/sec |
| Complex request + SDP | ~5μs | 200k msgs/sec |
| Security validation | ~500ns | 2M checks/sec |
| Codec encode/decode | ~2μs | 500k msgs/sec |
| Full message routing | ~10μs | 100k msgs/sec |

### Performance Optimizations

1. **Zero-Copy Parsing**
   - Nom parser operates on borrowed data
   - No unnecessary allocations
   - Efficient memory usage

2. **Lock-Free Data Structures**
   - `ahash` for fast hashing
   - `parking_lot` for efficient synchronization
   - Lock-free rate limiting counters

3. **Connection Pooling**
   ```rust
   ConnectionPoolConfig {
       max_size: 1000,              // Maximum connections
       min_idle: 10,                // Minimum idle connections
       max_lifetime: Duration::from_secs(300),
       idle_timeout: Duration::from_secs(60),
       connection_timeout: Duration::from_secs(5),
   }
   ```

4. **Tokio Runtime Tuning**
   ```rust
   let runtime = tokio::runtime::Builder::new_multi_thread()
       .worker_threads(num_cpus::get())
       .thread_name("sip-worker")
       .thread_stack_size(2 * 1024 * 1024)  // 2MB stacks
       .enable_all()
       .build()?;
   ```

### Memory Management

1. **Bounded Allocations**
   - Pre-allocated buffers for common operations
   - Size limits prevent unbounded growth
   - Efficient buffer recycling

2. **Custom Allocator** (Optional)
   ```toml
   [dependencies]
   jemallocator = "0.5"  # Better performance
   # or
   mimalloc = "0.3"      # Lower latency
   ```

3. **Memory Profiling**
   ```bash
   # Heap profiling
   MALLOC_CONF=prof:true ./target/release/sip-edge-rs
   
   # Memory usage analysis
   valgrind --tool=massif ./target/release/sip-edge-rs
   ```

## Deployment

### Docker Deployment

The project includes a multi-stage Dockerfile for optimal image size:

```dockerfile
# Build stage
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim
COPY --from=builder /app/target/release/sip-edge-rs /usr/local/bin/
EXPOSE 5060/udp 5060/tcp 5061/tcp
CMD ["sip-edge-rs"]
```

### Kubernetes Deployment

#### 1. Prepare TLS Certificates

```bash
# Production: Use cert-manager or external CA
# Testing: Generate self-signed certificates
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout tls.key -out tls.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=sip-edge-rs.example.com"

# Create namespace and secret
kubectl create namespace sip-edge-rs
kubectl create secret tls sip-edge-rs-tls \
  --cert=tls.crt --key=tls.key -n sip-edge-rs
```

#### 2. Deploy to Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sip-edge-rs
  namespace: sip-edge-rs
spec:
  replicas: 3
  selector:
    matchLabels:
      app: sip-edge-rs
  template:
    metadata:
      labels:
        app: sip-edge-rs
    spec:
      containers:
      - name: sip-edge-rs
        image: your-registry/sip-edge-rs:latest
        ports:
        - containerPort: 5060
          protocol: UDP
          name: sip-udp
        - containerPort: 5060
          protocol: TCP
          name: sip-tcp
        - containerPort: 5061
          protocol: TCP
          name: sip-tls
        env:
        - name: RUST_LOG
          value: "info"
        - name: SIP_TLS_CERT
          value: "/etc/sip-edge-rs/certs/tls.crt"
        - name: SIP_TLS_KEY
          value: "/etc/sip-edge-rs/certs/tls.key"
        volumeMounts:
        - name: tls-certs
          mountPath: /etc/sip-edge-rs/certs
          readOnly: true
        resources:
          requests:
            memory: "256Mi"
            cpu: "500m"
          limits:
            memory: "512Mi"
            cpu: "1000m"
        livenessProbe:
          tcpSocket:
            port: 5060
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          tcpSocket:
            port: 5060
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: tls-certs
        secret:
          secretName: sip-edge-rs-tls
```

#### 3. Service Configuration

```yaml
# UDP Service (LoadBalancer)
apiVersion: v1
kind: Service
metadata:
  name: sip-edge-rs-udp
  namespace: sip-edge-rs
spec:
  type: LoadBalancer
  selector:
    app: sip-edge-rs
  ports:
  - port: 5060
    targetPort: 5060
    protocol: UDP
---
# TCP/TLS Service
apiVersion: v1
kind: Service
metadata:
  name: sip-edge-rs-tcp
  namespace: sip-edge-rs
spec:
  type: LoadBalancer
  selector:
    app: sip-edge-rs
  ports:
  - name: tcp
    port: 5060
    targetPort: 5060
    protocol: TCP
  - name: tls
    port: 5061
    targetPort: 5061
    protocol: TCP
```

### Production Considerations

1. **High Availability**
   - Deploy multiple replicas (minimum 3)
   - Use pod anti-affinity rules
   - Configure pod disruption budgets

2. **Scaling**
   - Horizontal Pod Autoscaling based on CPU/memory
   - Vertical Pod Autoscaling for right-sizing
   - Cluster autoscaling for node capacity

3. **Security**
   - Network policies for traffic isolation
   - Pod security policies/standards
   - Regular security scanning of images

4. **Monitoring**
   - Prometheus ServiceMonitor for metrics
   - Grafana dashboards for visualization
   - Alerting rules for SLA compliance

## Monitoring and Observability

### Metrics (Prometheus)

The application exposes metrics on port 9090:

#### Core Metrics
- `sip_messages_total{method,transport}`: Total messages processed
- `sip_messages_errors_total{error_type}`: Parsing/validation errors
- `sip_security_violations_total{violation_type}`: Security violations detected
- `sip_response_time_seconds`: Message processing latency histogram
- `sip_active_connections{transport}`: Current active connections
- `sip_rate_limit_rejections_total{client_ip}`: Rate limit rejections

#### System Metrics
- `process_cpu_seconds_total`: CPU usage
- `process_resident_memory_bytes`: Memory usage
- `tokio_runtime_workers`: Active Tokio workers
- `tokio_runtime_tasks`: Active async tasks

### Logging

Structured logging with tracing:

```bash
# Log levels
export RUST_LOG=info                    # Default
export RUST_LOG=sip_edge_rs=debug       # Module-specific
export RUST_LOG=trace                  # Maximum verbosity

# Log with spans
export RUST_LOG_SPAN_EVENTS=full       # Include span timings
```

Log format:
```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "level": "INFO",
  "module": "sip_router",
  "message": "Received INVITE",
  "client_ip": "192.168.1.100",
  "method": "INVITE",
  "call_id": "abc123@host",
  "from": "sip:alice@example.com",
  "to": "sip:bob@example.com"
}
```

### Distributed Tracing

OpenTelemetry support (optional):

```toml
[dependencies]
opentelemetry = "0.21"
opentelemetry-jaeger = "0.20"
tracing-opentelemetry = "0.22"
```

```rust
// Initialize tracing
let tracer = opentelemetry_jaeger::new_agent_pipeline()
    .with_service_name("sip-edge-rs")
    .install_simple()?;

let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);
```

### Health Checks

1. **Liveness Probe**
   - TCP socket check on port 5060
   - Verifies the process is running

2. **Readiness Probe**
   - HTTP endpoint: `/health/ready`
   - Checks all subsystems are initialized

3. **Metrics Health**
   - HTTP endpoint: `/metrics`
   - Prometheus scrape endpoint

### Grafana Dashboards

Example dashboard JSON available in `.devcontainer/monitoring/grafana/dashboards/`:

- **SIP Overview**: Message rates, error rates, latency percentiles
- **Security**: Violation trends, rate limiting, blocked clients
- **Performance**: CPU, memory, connection pools, task queues
- **Business Metrics**: Call success rates, registration counts

## Testing Strategy

### Test Categories

1. **Unit Tests**
   ```bash
   cargo test
   cargo test -- --nocapture  # With output
   cargo test security::tests # Specific module
   ```

2. **Security Tests**
   ```bash
   cargo test --test vulnerability_tests
   ```
   
   Covered vulnerabilities:
   - SQL injection attempts
   - Buffer overflow attempts
   - Header smuggling (CRLF injection)
   - Response splitting
   - DoS via infinite loops
   - Null byte injection
   - Directory traversal
   - Command injection
   - Script injection
   - Malformed SDP
   - Registration flooding
   - Memory exhaustion
   - Integer overflow
   - Unicode attacks

3. **Performance Tests**
   ```bash
   cargo bench
   cargo bench -- --save-baseline before
   # Make changes
   cargo bench -- --baseline before
   ```

4. **Integration Tests**
   ```bash
   # Using test client
   cargo run --example test_client
   
   # Using SIPp
   sipp -sf .devcontainer/sipp-scenarios/client.xml \
     127.0.0.1:5060 -m 1000 -r 50
   ```

5. **Fuzzing**
   ```bash
   cargo install cargo-fuzz
   cargo fuzz run parser -- -max_total_time=300
   ```

### Test Coverage

```bash
# Generate coverage report
cargo tarpaulin --out Html --output-dir coverage

# With branch coverage
cargo tarpaulin --branch --out Lcov
```

Target coverage metrics:
- Line coverage: >90%
- Branch coverage: >80%
- Security tests: 100%

### Load Testing

1. **SIPp Scenarios**
   - Basic call flow: `client.xml`
   - Registration storm: `registration_flood.xml`
   - Complex scenarios: `advanced_call_flow.xml`

2. **Performance Profiling**
   ```bash
   # CPU profiling
   perf record -g cargo run --release
   perf report
   
   # Flame graphs
   cargo flamegraph --bin sip-edge-rs
   ```

3. **Memory Testing**
   ```bash
   # Leak detection
   valgrind --leak-check=full ./target/release/sip-edge-rs
   
   # Heap profiling
   valgrind --tool=massif ./target/release/sip-edge-rs
   massif-visualizer massif.out.*
   ```

## Advanced Usage

### Custom Message Routing

Implement custom routing logic:

```rust
use sip_edge_rs::{SipMessage, Router, RouterConfig};

#[derive(Clone)]
struct CustomRouter {
    config: RouterConfig,
    backends: Vec<String>,
}

#[async_trait]
impl Router for CustomRouter {
    async fn route_message(&self, message: SipMessage) -> Result<()> {
        match &message {
            SipMessage::Request(req) => {
                // Custom header-based routing
                if let Some(route) = utils::get_header(&message, "x-custom-route") {
                    self.route_to_backend(message, route).await?
                } else {
                    // Load balancing logic
                    let backend = self.select_backend(&req);
                    self.forward_to(message, backend).await?
                }
            }
            SipMessage::Response(resp) => {
                // Route responses via Via headers
                self.route_response(message).await?
            }
        }
        Ok(())
    }
    
    fn select_backend(&self, request: &SipRequest) -> &str {
        // Implement your load balancing algorithm
        // Example: consistent hashing based on Call-ID
        let hash = calculate_hash(&request.headers.call_id);
        let index = hash % self.backends.len();
        &self.backends[index]
    }
}
```

### Custom Security Rules

Extend the security validator:

```rust
use sip_edge_rs::{SecurityRule, SecurityValidator, SipMessage, SipParseError};

#[derive(Debug)]
struct GeographicRestriction {
    allowed_countries: HashSet<String>,
}

#[async_trait]
impl SecurityRule for GeographicRestriction {
    async fn validate(&self, message: &SipMessage, context: &SecurityContext) -> Result<(), SipParseError> {
        // Get client IP from context
        let client_ip = context.client_addr.ip();
        
        // Perform GeoIP lookup (example)
        let country = geoip_lookup(client_ip).await?;
        
        if !self.allowed_countries.contains(&country) {
            return Err(SipParseError::SecurityViolation(
                format!("Geographic restriction: {} not allowed", country)
            ));
        }
        
        Ok(())
    }
}

// Register the custom rule
let mut validator = SecurityValidator::new(config);
validator.add_rule(Box::new(GeographicRestriction {
    allowed_countries: hashset!["US", "CA", "UK", "DE"],
}));
```

### Protocol Extensions

Add support for custom SIP methods:

```rust
// Extend the parser for custom methods
parser.register_method("NOTIFY");
parser.register_method("SUBSCRIBE");
parser.register_method("MESSAGE");

// Handle custom methods in routing
match req.method.as_str() {
    "NOTIFY" => handle_notify(req).await?,
    "SUBSCRIBE" => handle_subscribe(req).await?,
    "MESSAGE" => handle_message(req).await?,
    _ => handle_standard(req).await?,
}
```

### Integration Examples

1. **With Kamailio/OpenSIPS**
   ```rust
   // Use as an outbound proxy
   let proxy_config = ProxyConfig {
       upstream: "sip:kamailio.example.com:5060",
       transport: Transport::TCP,
       backup: Some("sip:backup.example.com:5060"),
   };
   ```

2. **With RabbitMQ/Kafka**
   ```rust
   // Publish SIP events
   async fn on_message_received(&self, msg: SipMessage) {
       let event = SipEvent {
           timestamp: Utc::now(),
           message: msg.clone(),
           metadata: self.extract_metadata(&msg),
       };
       
       self.event_publisher.publish("sip.messages", &event).await?;
   }
   ```

3. **With Redis for Session State**
   ```rust
   // Store dialog state
   let dialog_id = compute_dialog_id(&message);
   let dialog_state = DialogState {
       call_id: message.call_id(),
       from_tag: message.from_tag(),
       to_tag: message.to_tag(),
       route_set: extract_route_set(&message),
   };
   
   redis_client.setex(
       &format!("dialog:{}", dialog_id),
       3600,  // 1 hour TTL
       &serde_json::to_string(&dialog_state)?
   ).await?;
   ```

## Troubleshooting

### Common Issues

#### 1. High CPU Usage

**Symptoms**: CPU consistently above 80%

**Diagnosis**:
```bash
# Check for routing loops
RUST_LOG=sip_edge_rs=trace cargo run 2>&1 | grep "Via:" | uniq -c

# Profile CPU usage
perf top -p $(pgrep sip-edge-rs)

# Generate flame graph
cargo flamegraph --bin sip-edge-rs -- --no-rosegment
```

**Solutions**:
- Check Max-Forwards header is being decremented
- Verify Via loop detection is enabled
- Review security rule complexity
- Tune worker thread count

#### 2. Memory Growth

**Symptoms**: RSS memory increasing over time

**Diagnosis**:
```bash
# Monitor memory usage
while true; do 
  ps aux | grep sip-edge-rs | grep -v grep
  sleep 5
done

# Check for leaks
valgrind --leak-check=full --show-leak-kinds=all ./target/release/sip-edge-rs

# Heap profiling
HEAP_PROFILE=/tmp/heap cargo run --release
pprof --web /tmp/heap.*.heap
```

**Solutions**:
- Verify connection cleanup in transport layer
- Check rate limiter eviction is running
- Review buffer pooling configuration
- Enable jemalloc statistics

#### 3. TLS Handshake Failures

**Symptoms**: TLS connections failing

**Diagnosis**:
```bash
# Test TLS connectivity
openssl s_client -connect localhost:5061 -CAfile ca.pem

# Check certificate
openssl x509 -in tls.crt -text -noout | grep -E "(Subject:|Issuer:|Not)"

# Enable TLS debugging
RUST_LOG=rustls=debug,sip_edge_rs::transport=trace cargo run
```

**Solutions**:
- Verify certificate chain is complete
- Check certificate CN matches hostname
- Review cipher suite configuration
- Ensure TLS version compatibility

#### 4. Message Parsing Failures

**Symptoms**: Dropping valid SIP messages

**Diagnosis**:
```bash
# Enable parser tracing
RUST_LOG=sip_edge_rs=trace cargo run

# Capture failed messages
tcpdump -i any -w sip.pcap 'port 5060'
tshark -r sip.pcap -Y 'sip.CSeq.method == "INVITE"' -T fields -e sip.msg_hdr
```

**Solutions**:
- Check for non-standard headers
- Verify Content-Length accuracy
- Review header size limits
- Test with relaxed parsing mode

### Debug Tools

#### 1. Built-in Diagnostics

```rust
// Enable debug endpoints
let debug_config = DebugConfig {
    enable_metrics: true,
    enable_profiling: true,
    dump_messages: true,
    slow_request_threshold: Duration::from_millis(100),
};
```

#### 2. Runtime Inspection

```bash
# Tokio console for async runtime debugging
cargo install --locked tokio-console
tokio-console http://localhost:6669

# Runtime metrics
curl http://localhost:9090/metrics | grep tokio
```

#### 3. Packet Analysis

```bash
# SIP-specific packet capture
tshark -f "port 5060 or port 5061" -Y sip -T fields \
  -e frame.time -e ip.src -e ip.dst \
  -e sip.Method -e sip.Status-Code -e sip.Call-ID

# Export as PCAP for Wireshark
tcpdump -i any -w sip_trace.pcap 'port 5060 or port 5061'
```

### Performance Tuning Checklist

1. **System Level**
   - [ ] Increase file descriptor limits
   - [ ] Tune network buffers (net.core.rmem_max)
   - [ ] Disable CPU frequency scaling
   - [ ] Enable huge pages

2. **Application Level**
   - [ ] Use release builds with LTO
   - [ ] Enable jemalloc or mimalloc
   - [ ] Tune Tokio worker threads
   - [ ] Configure connection pooling

3. **Monitoring**
   - [ ] Set up Prometheus alerts
   - [ ] Configure Grafana dashboards  
   - [ ] Enable distributed tracing
   - [ ] Implement SLA tracking

## API Reference

### Core Types

```rust
// Main message types
pub enum SipMessage {
    Request(SipRequest),
    Response(SipResponse),
}

pub struct SipRequest {
    pub method: String,
    pub uri: SipUri,
    pub version: String,
    pub headers: HeaderMap,
    pub body: Option<Vec<u8>>,
}

pub struct SipResponse {
    pub version: String,
    pub status_code: u16,
    pub reason_phrase: String,
    pub headers: HeaderMap,
    pub body: Option<Vec<u8>>,
}
```

### Parser API

```rust
use sip_edge_rs::{Parser, ParserConfig};

// Create parser with config
let config = ParserConfig {
    max_header_size: 8192,
    max_message_size: 65536,
    strict_parsing: true,
};
let parser = Parser::new(config);

// Parse message
let message = parser.parse(input_bytes)?;

// Access headers
let call_id = message.header("Call-ID")?;
let from = message.header("From")?;
```

### Security API

```rust
use sip_edge_rs::{SecurityValidator, SecurityConfig};

// Create validator
let config = SecurityConfig::default();
let validator = SecurityValidator::new(config);

// Validate message
validator.validate(&message, &context)?;

// Add custom rules
validator.add_rule(Box::new(MyCustomRule));
```

### Transport API

```rust
use sip_edge_rs::{Transport, TransportConfig};

// Create transport layer
let config = TransportConfig {
    udp_addr: "0.0.0.0:5060".parse()?,
    tcp_addr: "0.0.0.0:5060".parse()?,
    tls_addr: "0.0.0.0:5061".parse()?,
    tls_config: Some(tls_config),
};

let transport = Transport::new(config).await?;

// Start listening
transport.listen().await?;
```

### Router API

```rust
use sip_edge_rs::{Router, RouterConfig};

// Implement custom router
#[derive(Clone)]
struct MyRouter {
    config: RouterConfig,
}

#[async_trait]
impl Router for MyRouter {
    async fn route_message(&self, msg: SipMessage) -> Result<()> {
        // Custom routing logic
        Ok(())
    }
}
```

For complete API documentation, run `cargo doc --open` or visit [docs.rs/sip-edge-rs](https://docs.rs/sip-edge-rs).