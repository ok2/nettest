# NetTest - Network Connectivity Testing Tool

A comprehensive command-line tool written in Rust for testing network connectivity and DNS resolution across various dimensions.

## Features

### Network Testing
- **IPv4 and IPv6 support** - Test connectivity using both IP versions
- **Multiple protocols** - Support for TCP, UDP, and ICMP
- **Port testing** - Test common ports and custom port ranges
- **Timeout configuration** - Configurable timeouts for all tests

### MTU Discovery
- **Binary search MTU discovery** - Efficiently find the maximum MTU size
- **Common MTU testing** - Test standard MTU sizes (68, 576, 1280, 1500, 4464, 9000)
- **Custom range testing** - Test specific MTU ranges
- **IPv4 and IPv6 support** - MTU discovery for both IP versions

### DNS Testing
- **Comprehensive record types** - A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, and more
- **Multiple DNS servers** - Test against Google, Cloudflare, Quad9, OpenDNS, and others
- **TCP and UDP queries** - Support for both DNS transport protocols
- **Large query testing** - Test handling of large DNS responses
- **International domains** - Support for IDN (Internationalized Domain Names)

### Domain Category Testing
- **Normal websites** - Test legitimate, commonly used sites
- **Ad networks** - Test advertising and tracking domains
- **Spam domains** - Test temporary email and spam-associated domains  
- **Adult content** - Test adult content sites (often filtered)
- **Malicious domains** - Test known malicious/phishing domains
- **Social media** - Test major social media platforms
- **Streaming services** - Test video and music streaming sites
- **Gaming platforms** - Test gaming services and platforms
- **News websites** - Test major news and media sites

### DNS Filtering Analysis
- **Filter effectiveness** - Analyze how well DNS filtering is working
- **Category-based analysis** - See which categories are being blocked
- **Detailed reporting** - Get statistics on resolution success rates

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd nettest

# Build the project
cargo build --release

# Install globally (optional)
cargo install --path .
```

## Usage

### Basic Commands

```bash
# Run comprehensive tests on a target
nettest full google.com

# Test TCP connectivity
nettest network tcp google.com --port 80

# Test UDP connectivity  
nettest network udp 8.8.8.8 --port 53

# Ping test
nettest network ping google.com --count 4

# Test common ports
nettest network ports google.com --protocol tcp

# DNS query
nettest dns query google.com --record-type a

# Test DNS servers
nettest dns servers google.com

# Test domain categories
nettest dns categories --category normal

# MTU discovery
nettest mtu discover google.com

# Test common MTU sizes
nettest mtu common google.com
```

### Advanced Options

```bash
# Specify IP version
nettest network tcp google.com --ip-version v4
nettest network tcp google.com --ip-version v6
nettest network tcp google.com --ip-version both

# Custom timeout
nettest --timeout 10 network tcp google.com

# JSON output
nettest --json dns query google.com

# Verbose logging
nettest --verbose full google.com

# DNS query with specific server
nettest dns query google.com --server 8.8.8.8:53 --tcp

# Custom MTU range
nettest mtu range google.com --min 1000 --max 1500
```

### Domain Category Testing

Test different categories of domains to analyze DNS filtering:

```bash
# Test normal websites
nettest dns categories --category normal

# Test ad networks
nettest dns categories --category ads

# Test all categories
nettest dns categories --category all

# DNS filtering effectiveness
nettest dns filtering
```

### Comprehensive Testing

The `full` command runs a comprehensive suite of tests:

```bash
# Full test suite for a domain
nettest full example.com

# Full test with specific IP version
nettest full example.com --ip-version v4
```

This includes:
- TCP and UDP connectivity tests
- ICMP ping tests  
- MTU discovery
- DNS resolution tests
- DNS server tests

## Output Formats

### Human-readable (default)
Colored, formatted output suitable for terminal viewing.

### JSON
Machine-readable JSON output for integration with other tools:

```bash
nettest --json dns query google.com
```

## Requirements

- Rust 1.70 or later
- Root/administrator privileges may be required for:
  - ICMP ping tests
  - Raw socket operations
  - MTU discovery

## Testing

Run the test suite:

```bash
# Unit tests
cargo test

# Integration tests
cargo test --test integration_tests

# All tests with verbose output
cargo test -- --nocapture
```

## Architecture

The tool is organized into several modules:

- **cli** - Command-line argument parsing and interface
- **network** - TCP, UDP, and ICMP connectivity testing
- **dns** - DNS resolution and query testing
- **mtu** - MTU discovery and testing
- **utils** - Common utilities and error handling

## Security Considerations

This tool is designed for defensive security testing and network diagnostics. It:

- Tests legitimate connectivity to verify network functionality
- Analyzes DNS filtering effectiveness
- Discovers network path characteristics
- Does not attempt to exploit or attack systems
- Respects rate limits and timeouts

## License

[Add your license here]

## Contributing

[Add contribution guidelines here]