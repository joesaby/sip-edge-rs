#!/bin/bash

set -e

echo "🚀 Setting up SIP Router development environment..."

# Update package lists
sudo apt-get update

# Install additional packages for SIP development and testing
echo "📦 Installing additional packages..."
sudo apt-get install -y \
    netcat-openbsd \
    tcpdump \
    wireshark-common \
    tshark \
    nmap \
    telnet \
    socat \
    iperf3 \
    htop \
    tree \
    jq \
    curl \
    wget \
    git \
    build-essential \
    pkg-config \
    libssl-dev \
    protobuf-compiler

# Install Rust toolchain components
echo "🦀 Installing Rust toolchain components..."
rustup component add clippy rustfmt
rustup target add x86_64-unknown-linux-musl

# Fix cargo registry permissions for the vscode user
echo "🔧 Fixing cargo registry permissions..."
sudo mkdir -p /usr/local/cargo/registry
sudo chown -R vscode:rustlang /usr/local/cargo/registry || sudo chown -R vscode:vscode /usr/local/cargo/registry
sudo chmod -R 775 /usr/local/cargo/registry

# Setup cache directories with proper permissions
echo "🗂️  Setting up cache directories..."
sudo mkdir -p /usr/local/cargo/git
sudo chown -R vscode:rustlang /usr/local/cargo/git || sudo chown -R vscode:vscode /usr/local/cargo/git
sudo chmod -R 775 /usr/local/cargo/git

# Ensure target directory has correct permissions
mkdir -p /workspaces/sip-edge-rs/target
chown -R vscode:vscode /workspaces/sip-edge-rs/target || true
chmod -R 755 /workspaces/sip-edge-rs/target

# Install cargo tools for development
echo "📦 Installing cargo tools..."
cargo install \
    cargo-watch \
    cargo-edit \
    cargo-tree \
    cargo-audit \
    cargo-deny \
    cargo-tarpaulin \
    cargo-benchcmp \
    cargo-expand \
    cargo-flamegraph \
    sccache \
    cargo-nextest

# Setup sccache for faster builds
echo "⚡ Configuring sccache for faster builds..."
echo 'export RUSTC_WRAPPER=sccache' >> ~/.bashrc
echo 'export RUSTC_WRAPPER=sccache' >> ~/.zshrc

# Install SIP testing tools
echo "📞 Installing SIP testing tools..."
# SIPp - SIP testing tool
cd /tmp
wget https://github.com/SIPp/sipp/releases/download/v3.7.2/sipp-3.7.2.tar.gz
tar -xzf sipp-3.7.2.tar.gz
cd sipp-3.7.2
sudo apt-get install -y libncurses5-dev libncursesw5-dev
./configure --enable-pcap --enable-rtpstream
make -j$(nproc)
sudo make install
cd /workspaces/sip-edge-rs

# Create useful aliases
echo "🔧 Setting up aliases..."
cat >> ~/.zshrc << 'EOF'

# SIP Router Development Aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias cr='cargo run'
alias cb='cargo build'
alias ct='cargo test'
alias cc='cargo check'
alias cw='cargo watch -x check -x test -x run'
alias bench='cargo bench'
alias audit='cargo audit'
alias fmt='cargo fmt'
alias clippy='cargo clippy -- -D warnings'
alias coverage='cargo tarpaulin --out Html'

# SIP testing aliases
alias sipp-client='sipp -sf /workspaces/sip-edge-rs/.devcontainer/sipp-scenarios/client.xml'
alias sipp-server='sipp -sf /workspaces/sip-edge-rs/.devcontainer/sipp-scenarios/server.xml'

# Network debugging
alias siplog='tshark -i any -f "port 5060 or port 5061" -Y sip'
alias netstat-sip='netstat -tulpn | grep -E "506[01]"'

EOF

# Create SIPp scenarios directory
mkdir -p .devcontainer/sipp-scenarios

# Create basic SIPp client scenario
cat > .devcontainer/sipp-scenarios/client.xml << 'EOF'
<?xml version="1.0" encoding="ISO-8859-1" ?>
<!DOCTYPE scenario SYSTEM "sipp.dtd">

<scenario name="Basic SIP Client">
  <send retrans="500">
    <![CDATA[
      INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
      To: [service] <sip:[service]@[remote_ip]:[remote_port]>
      Call-ID: [call_id]
      CSeq: 1 INVITE
      Contact: sip:sipp@[local_ip]:[local_port]
      Max-Forwards: 70
      Subject: Performance Test
      Content-Type: application/sdp
      Content-Length: [len]

      v=0
      o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]
      s=-
      c=IN IP[media_ip_type] [media_ip]
      t=0 0
      m=audio [media_port] RTP/AVP 0
      a=rtpmap:0 PCMU/8000

    ]]>
  </send>

  <recv response="100" optional="true">
  </recv>

  <recv response="180" optional="true">
  </recv>

  <recv response="183" optional="true">
  </recv>

  <recv response="200" rtd="true">
  </recv>

  <send>
    <![CDATA[
      ACK sip:[service]@[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
      To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
      Call-ID: [call_id]
      CSeq: 1 ACK
      Contact: sip:sipp@[local_ip]:[local_port]
      Max-Forwards: 70
      Subject: Performance Test
      Content-Length: 0

    ]]>
  </send>

  <pause milliseconds="5000"/>

  <send retrans="500">
    <![CDATA[
      BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
      From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
      To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
      Call-ID: [call_id]
      CSeq: 2 BYE
      Contact: sip:sipp@[local_ip]:[local_port]
      Max-Forwards: 70
      Subject: Performance Test
      Content-Length: 0

    ]]>
  </send>

  <recv response="200" crlf="true">
  </recv>

  <ResponseTimeRepartition value="10, 20, 30, 40, 50, 100, 150, 200"/>
  <CallLengthRepartition value="10, 50, 100, 500, 1000, 5000, 10000"/>

</scenario>
EOF

# Create basic SIPp server scenario
cat > .devcontainer/sipp-scenarios/server.xml << 'EOF'
<?xml version="1.0" encoding="ISO-8859-1" ?>
<!DOCTYPE scenario SYSTEM "sipp.dtd">

<scenario name="Basic SIP Server">
  <recv request="INVITE" crlf="true">
  </recv>

  <send>
    <![CDATA[
      SIP/2.0 180 Ringing
      [last_Via:]
      [last_From:]
      [last_To:];tag=[pid]SIPpTag01[call_number]
      [last_Call-ID:]
      [last_CSeq:]
      Contact: <sip:[local_ip]:[local_port];transport=[transport]>
      Content-Length: 0

    ]]>
  </send>

  <send retrans="500">
    <![CDATA[
      SIP/2.0 200 OK
      [last_Via:]
      [last_From:]
      [last_To:];tag=[pid]SIPpTag01[call_number]
      [last_Call-ID:]
      [last_CSeq:]
      Contact: <sip:[local_ip]:[local_port];transport=[transport]>
      Content-Type: application/sdp
      Content-Length: [len]

      v=0
      o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]
      s=-
      c=IN IP[media_ip_type] [media_ip]
      t=0 0
      m=audio [media_port] RTP/AVP 0
      a=rtpmap:0 PCMU/8000

    ]]>
  </send>

  <recv request="ACK" rtd="true" crlf="true">
  </recv>

  <recv request="BYE" crlf="true">
  </recv>

  <send>
    <![CDATA[
      SIP/2.0 200 OK
      [last_Via:]
      [last_From:]
      [last_To:]
      [last_Call-ID:]
      [last_CSeq:]
      Content-Length: 0

    ]]>
  </send>

  <ResponseTimeRepartition value="10, 20, 30, 40, 50, 100, 150, 200"/>
  <CallLengthRepartition value="10, 50, 100, 500, 1000, 5000, 10000"/>

</scenario>
EOF

# Create test certificates for TLS testing
echo "🔐 Creating test certificates for TLS testing..."
mkdir -p .devcontainer/certs
cd .devcontainer/certs

# Generate CA private key
openssl genrsa -out ca-key.pem 4096

# Generate CA certificate
openssl req -new -x509 -days 365 -key ca-key.pem -sha256 -out ca.pem -subj "/C=US/ST=Test/L=Test/O=SIP Router Dev/CN=Test CA"

# Generate server private key
openssl genrsa -out server-key.pem 4096

# Generate server certificate signing request
openssl req -subj "/C=US/ST=Test/L=Test/O=SIP Router Dev/CN=localhost" -new -key server-key.pem -out server.csr

# Generate server certificate
openssl x509 -req -days 365 -in server.csr -CA ca.pem -CAkey ca-key.pem -out server-cert.pem -extensions v3_req -extfile <(echo -e "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:0.0.0.0")

# Set proper permissions
chmod 600 *-key.pem
chmod 644 *.pem

cd /workspaces/sip-edge-rs

# Pre-build dependencies to speed up subsequent builds
echo "🏗️  Pre-building dependencies..."
cargo fetch
cargo build --release

# Run initial tests to verify setup
echo "🧪 Running initial tests..."
cargo test --quiet

echo "✅ Development environment setup complete!"
echo ""
echo "🚀 Quick start commands:"
echo "  cargo run              - Run the SIP router"
echo "  cargo test             - Run all tests"
echo "  cargo bench            - Run benchmarks"
echo "  cargo watch -x check   - Watch for changes and check"
echo "  sipp-client 127.0.0.1  - Test with SIPp client"
echo ""
echo "🔍 Debugging commands:"
echo "  siplog                 - Monitor SIP traffic with tshark"
echo "  netstat-sip            - Check SIP port status"
echo ""
echo "📖 See README.md for more information" 