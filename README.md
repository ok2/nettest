# NetTest 🌐

A comprehensive network connectivity and DNS testing CLI tool written in Rust. NetTest provides extensive testing capabilities for network diagnostics, DNS resolution (including DNS-over-HTTPS), MTU discovery, and connectivity analysis.

[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)
[![License: WTFPL](https://img.shields.io/badge/License-WTFPL-brightgreen.svg)](http://www.wtfpl.net/about/)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](#testing)

## Features

- **🌐 Network Connectivity Testing**: TCP, UDP, and ICMP ping tests with IPv4/IPv6 support
- **🔍 DNS Resolution Testing**: Comprehensive DNS testing with 23 traditional DNS servers
- **🚀 DNS-over-HTTPS (DoH) Support**: 16 DoH providers with JSON and Wire format support
- **📏 MTU Discovery**: Automated MTU path discovery and common size testing
- **🛡️ Security Analysis**: DNS filtering, sinkhole detection, and security categorization
- **⚡ High Performance**: Async/concurrent testing with progress indicators
- **📊 Multiple Output Formats**: Human-readable and JSON output formats

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/NetTest.git
cd NetTest

# Build the project
cargo build --release

# Run tests (optional)
cargo test
```

### Basic Usage

```bash
# Full network test suite
./target/release/nettest full google.com

# Test DNS resolution
./target/release/nettest dns query google.com

# Test all DNS servers
./target/release/nettest dns servers google.com

# Test DNS-over-HTTPS
./target/release/nettest dns doh google.com

# Test network connectivity
./target/release/nettest network ping google.com --count 5

# Discover MTU
./target/release/nettest mtu discover google.com
```

## Comprehensive Command Reference

### Network Testing

#### TCP Connectivity
```bash
# Test TCP connection to port 80
nettest network tcp google.com --port 80

# Test specific IP versions
nettest network tcp google.com --ip-version v4
nettest network tcp google.com --ip-version v6
nettest network tcp google.com --ip-version both

# Test with custom timeout
nettest network tcp google.com --port 443 --timeout 10
```

#### UDP Connectivity
```bash
# Test UDP connection to DNS port
nettest network udp 8.8.8.8 --port 53

# Test multiple IP versions
nettest network udp cloudflare.com --port 53 --ip-version both
```

#### ICMP Ping Testing
```bash
# Basic ping test
nettest network ping google.com

# Extended ping with count
nettest network ping google.com --count 10

# Ping with sudo for more accurate results
nettest network ping google.com --count 5 --sudo

# IPv6 ping testing
nettest network ping google.com --ip-version v6
```

#### Port Scanning
```bash
# Scan common TCP ports
nettest network ports google.com --protocol tcp

# Scan common UDP ports
nettest network ports google.com --protocol udp

# Scan both TCP and UDP
nettest network ports google.com --protocol both
```

### DNS Testing

#### Basic DNS Queries
```bash
# Query A records
nettest dns query google.com --record-type a

# Query different record types
nettest dns query google.com --record-type aaaa
nettest dns query google.com --record-type mx
nettest dns query google.com --record-type txt
nettest dns query google.com --record-type ns

# Query all record types
nettest dns query google.com --record-type all

# Query specific DNS server
nettest dns query google.com --server 8.8.8.8:53

# Use TCP instead of UDP
nettest dns query google.com --tcp
```

#### DNS Server Testing
```bash
# Test all 23 traditional DNS servers + 16 DoH providers (39 total)
nettest dns servers google.com

# Test with different record types
nettest dns servers google.com --record-type txt
nettest dns servers google.com --record-type mx
```

#### DNS-over-HTTPS (DoH) Testing
```bash
# Test all DoH providers
nettest dns doh google.com

# Test specific DoH provider
nettest dns doh google.com --provider google
nettest dns doh google.com --provider cloudflare
nettest dns doh google.com --provider quad9

# Available DoH providers:
# - google (wire format)
# - google-json (JSON format)
# - cloudflare (wire format)
# - cloudflare-json (JSON format)
# - cloudflare-family (blocks malware/adult)
# - cloudflare-family-json
# - cloudflare-security (blocks malware only)
# - cloudflare-security-json
# - quad9 (blocks malicious domains)
# - quad9-unsecured (no blocking)
# - quad9-ecs (with EDNS Client Subnet)
# - opendns
# - opendns-family (family filter)
# - adguard (blocks ads/trackers)
# - adguard-family (blocks ads/trackers/adult)
# - adguard-unfiltered (no filtering)

# List all available DoH providers
nettest dns doh-providers
```

#### Comprehensive DNS Testing
```bash
# Test all DNS record types with system resolver
nettest dns comprehensive google.com

# Test large DNS responses (TXT records)
nettest dns large google.com
```

#### DNS Security and Filtering
```bash
# Test DNS filtering effectiveness
nettest dns filtering

# Test domain categories
nettest dns categories --category malicious
nettest dns categories --category ads
nettest dns categories --category adult
nettest dns categories --category all

# Debug DNS configuration
nettest dns debug
```

### MTU Discovery

#### Automatic MTU Discovery
```bash
# Discover optimal MTU
nettest mtu discover google.com

# MTU discovery with sudo (more accurate)
nettest mtu discover google.com --sudo

# IPv6 MTU discovery
nettest mtu discover google.com --ip-version v6
```

#### Common MTU Testing
```bash
# Test common MTU sizes (1500, 1492, 1280, etc.)
nettest mtu common google.com

# With sudo for accurate results
nettest mtu common google.com --sudo
```

#### Custom MTU Range Testing
```bash
# Test custom MTU range
nettest mtu range google.com --min 1000 --max 1600

# Fine-grained range testing
nettest mtu range google.com --min 1400 --max 1500 --sudo
```

### Full Test Suite
```bash
# Comprehensive test suite
nettest full google.com

# Full test with sudo privileges
nettest full google.com --sudo

# IPv4 only comprehensive test
nettest full google.com --ip-version v4

# IPv6 only comprehensive test
nettest full google.com --ip-version v6
```

### Output Formats

#### Human-Readable Output (Default)
```bash
nettest dns servers google.com
```
Output:
```
================================================================================
Network Test Results
================================================================================
PASS DNS A query for google.com (UDP via System DNS) (24ms)
  ✓ A records: 142.250.191.14

PASS DNS A query for google.com (UDP via 8.8.8.8:53) (15ms)
  ✓ A records: 142.250.191.14 (via 8.8.8.8:53)

PASS DoH A query for google.com (via Google) (45ms)
  ✓ A records: 142.250.191.14
```

#### JSON Output
```bash
nettest dns query google.com --json
```
Output:
```json
[
  {
    "test_name": "DNS A query for google.com (UDP via System DNS)",
    "success": true,
    "duration_ms": 24,
    "details": "A records: 142.250.191.14"
  }
]
```

### Global Options

```bash
# Verbose logging
nettest --verbose dns query google.com

# Custom timeout (default: 5 seconds)
nettest --timeout 10 network tcp google.com

# JSON output format
nettest --json dns servers google.com
```

## Advanced Usage Examples

### Network Troubleshooting Workflow
```bash
# 1. Test basic connectivity
nettest network ping target.com --count 5

# 2. Test specific ports
nettest network tcp target.com --port 80
nettest network tcp target.com --port 443

# 3. Check DNS resolution
nettest dns query target.com --record-type a
nettest dns servers target.com

# 4. Test with different DNS servers
nettest dns query target.com --server 8.8.8.8:53
nettest dns query target.com --server 1.1.1.1:53

# 5. Test DNS-over-HTTPS
nettest dns doh target.com --provider cloudflare

# 6. Discover MTU issues
nettest mtu discover target.com
```

### DNS Security Analysis
```bash
# Test malicious domain blocking
nettest dns categories --category malicious

# Test ad blocking effectiveness
nettest dns categories --category ads

# Check for DNS filtering
nettest dns filtering

# Test with security-focused DNS servers
nettest dns doh malicious-domain.test --provider quad9
```

### Performance Comparison
```bash
# Compare DNS server performance
nettest dns servers google.com --json | jq '.[] | {name: .test_name, duration: .duration_ms}'

# Compare DoH vs traditional DNS
nettest dns query google.com --server 8.8.8.8:53 --json
nettest dns doh google.com --provider google --json
```

## DNS Providers

### Traditional DNS Servers (23 servers)
- **Google DNS**: 8.8.8.8, 8.8.4.4
- **Cloudflare DNS**: 1.1.1.1, 1.0.0.1, 1.1.1.2, 1.1.1.3
- **Quad9**: 9.9.9.9, 149.112.112.112, 9.9.9.10, 149.112.112.10, 9.9.9.11, 149.112.112.11
- **OpenDNS**: 208.67.222.222, 208.67.220.220, 208.67.222.123, 208.67.220.123
- **AdGuard DNS**: 94.140.14.14, 94.140.15.15, 94.140.14.15, 94.140.15.16, 94.140.14.140, 94.140.14.141

### DNS-over-HTTPS Providers (16 providers)
- **Google**: Wire format and JSON API
- **Cloudflare**: Standard, Family, Security variants in both formats
- **Quad9**: Standard, Unsecured, ECS variants
- **OpenDNS**: Standard and Family Shield
- **AdGuard**: Standard, Family, and Unfiltered variants

## Library Usage

NetTest can also be used as a Rust library:

```rust
use nettest::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // DNS testing
    let dns_test = dns::DnsTest::new("google.com".to_string(), hickory_client::rr::RecordType::A);
    let result = dns_test.run().await;
    println!("DNS test: {}", result.test_name);

    // Network testing
    let network_test = network::NetworkTest::new(
        "google.com".to_string(),
        network::IpVersion::V4,
        network::NetworkProtocol::Tcp,
    ).with_port(80);
    let result = network_test.run().await;
    println!("Network test: {}", result.test_name);

    // DoH testing
    let providers = dns::doh::DOH_PROVIDERS;
    let doh_test = dns::doh::DohTest::new(
        "google.com".to_string(),
        hickory_client::rr::RecordType::A,
        providers[0].clone()
    );
    let result = doh_test.run().await;
    println!("DoH test: {}", result.test_name);

    Ok(())
}
```

## Configuration

### Environment Variables
```bash
# Set default timeout
export NETTEST_TIMEOUT=10

# Enable verbose logging
export RUST_LOG=info

# For detailed DNS debugging
export RUST_LOG=nettest=debug
```

### Cargo Features
```toml
[dependencies]
nettest = { version = "1.0", features = ["all"] }

# Or specific features
nettest = { version = "1.0", features = ["dns", "doh", "network"] }
```

## Troubleshooting

### Common Issues

#### DNS TXT Record Timeouts
```bash
# NetTest automatically enables EDNS0 for large TXT records
# If you still experience timeouts, try:
nettest dns query google.com --record-type txt --timeout 15
```

#### Permission Issues with Ping/MTU
```bash
# Use sudo flag for accurate ICMP and MTU testing
nettest network ping google.com --sudo
nettest mtu discover google.com --sudo
```

#### IPv6 Connectivity Issues
```bash
# Test IPv6 connectivity first
nettest network ping google.com --ip-version v6
nettest dns query google.com --record-type aaaa
```

### Debug Information
```bash
# Show current DNS configuration
nettest dns debug

# Verbose output for troubleshooting
nettest --verbose dns query google.com
```

## Performance Benchmarks

### DNS Query Performance
Typical response times on a 100 Mbps connection:
- **Traditional DNS (UDP)**: 5-50ms
- **DNS-over-HTTPS**: 50-200ms
- **Large TXT records**: 10-100ms (with EDNS0)

### Concurrent Testing
NetTest performs concurrent tests where possible:
- DNS server testing: Up to 39 concurrent queries
- Network port scanning: Concurrent port tests
- DoH provider testing: Parallel HTTP requests

## Security Features

### DNS Sinkhole Detection
NetTest automatically detects common DNS sinkhole responses:
- `0.0.0.0` redirects
- Localhost redirects (`127.x.x.x`)
- Common DNS filtering IPs

### Security-Focused Testing
```bash
# Test security DNS providers
nettest dns doh malicious-site.test --provider quad9

# Check filtering effectiveness
nettest dns categories --category malicious
nettest dns filtering
```


## Testing

### Running Tests
```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test module
cargo test dns::

# Run doc tests
cargo test --doc
```

### Code Quality
```bash
# Check code formatting
cargo fmt --check

# Run linter
cargo clippy -- -D warnings

# Security audit
cargo audit
```

## Architecture

NetTest is built with a modular architecture for maintainability and extensibility:

```
src/
├── cli/          # Command-line interface and argument parsing  
├── network/      # Network connectivity testing
│   ├── icmp.rs   # ICMP ping tests with IPv6 support
│   ├── tcp.rs    # TCP connection testing
│   └── udp.rs    # UDP connectivity testing
├── dns/          # DNS testing and analysis
│   ├── categories.rs  # Domain category definitions
│   ├── queries.rs     # DNS query implementations  
│   └── mod.rs         # Core DNS logic with sinkhole detection
├── mtu/          # MTU discovery and testing
├── utils/        # Common utilities and error handling
└── main.rs       # Application entry point and orchestration
```

### Key Design Principles

- **Async-first**: All network operations are asynchronous for better performance
- **Error handling**: Comprehensive error handling with descriptive messages
- **Cross-platform**: Works on macOS, Linux, and Windows
- **IPv6 ready**: Full support for IPv6 alongside IPv4
- **Extensible**: Easy to add new test types and protocols

## Security Considerations

This tool is designed for defensive security testing and network diagnostics. It:

- Tests legitimate connectivity to verify network functionality
- Analyzes DNS filtering effectiveness
- Discovers network path characteristics
- Does not attempt to exploit or attack systems
- Respects rate limits and timeouts

## License

This project is licensed under the **WTFPL** (Do What The F*ck You Want To Public License) Version 2.

```
            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
                    Version 2, December 2004

 Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>

 Everyone is permitted to copy and distribute verbatim or modified
 copies of this license document, and changing it is allowed as long
 as the name is changed.

            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

  0. You just DO WHAT THE FUCK YOU WANT TO.
```

**TL;DR:** Do whatever you want with this code! 🎉

## Contributing

Since this project is licensed under WTFPL, you can do whatever you want! But if you'd like to contribute:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes and test**: `cargo test && cargo clippy`
4. **Commit your changes**: `git commit -m 'Add amazing feature'`
5. **Push to the branch**: `git push origin feature/amazing-feature` 
6. **Open a Pull Request**

### Development Setup

```bash
# Clone your fork
git clone https://github.com/your-username/nettest.git
cd nettest

# Install development dependencies
cargo build

# Run all quality checks
cargo fmt           # Format code
cargo clippy        # Lint code  
cargo test          # Run tests
cargo audit         # Security audit
```

### Code Quality

The project maintains high code quality standards:
- ✅ All tests must pass
- ✅ Zero clippy warnings  
- ✅ Proper formatting with rustfmt
- ✅ No security vulnerabilities
- ✅ Comprehensive error handling

