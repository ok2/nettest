# NetTest - Network Connectivity Testing Tool

A comprehensive command-line tool written in Rust for testing network connectivity, DNS resolution, and network path characteristics across IPv4 and IPv6.

**Key Features:**
- 🌐 Comprehensive IPv4/IPv6 connectivity testing
- 🔍 Advanced DNS testing with sinkhole detection
- 📊 MTU discovery and path analysis  
- 🛡️ DNS filtering effectiveness analysis
- 🚀 High-performance async implementation
- 📋 Human-readable and JSON output formats

## Quick Start

```bash
# Clone and build
git clone https://github.com/your-username/nettest.git
cd nettest && cargo build --release

# Run comprehensive tests
./target/release/nettest full google.com

# Test DNS with IPv6
./target/release/nettest network ping google.com --ip-version v6

# Check DNS filtering effectiveness  
./target/release/nettest dns filtering
```

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
- **Sinkhole detection** - Automatically detects DNS sinkholing (0.0.0.0, 127.0.0.1, etc.)
- **Smart error handling** - Distinguishes between DNS failures and missing records
- **System DNS integration** - Uses system DNS configuration while avoiding search domain expansion
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

### From Source

```bash
# Clone the repository
git clone https://github.com/your-username/nettest.git
cd nettest

# Build the project
cargo build --release

# Install globally (optional)
cargo install --path .
```

### Using Cargo

```bash
# Install directly from source (when published)
cargo install nettest
```

### Requirements

- Rust 1.70 or later
- Root/administrator privileges may be required for:
  - ICMP ping tests
  - Raw socket operations
  - Some MTU discovery operations

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

# Show system DNS configuration
nettest dns debug
```

### DNS Sinkhole Detection

NetTest automatically detects when domains are being sinkholed (redirected to special IP addresses):

```bash
# Example output showing sinkhole detection
$ nettest dns query blocked-domain.com --record-type a
PASS DNS A query for blocked-domain.com (UDP) (45ms)
  ✓ A records: 🕳️ SINKHOLED (security success): Redirected to sinkhole IPs: 0.0.0.0

# Example showing missing records (not an error)
$ nettest dns query image.example.com --record-type mx  
PASS DNS MX query for image.example.com (UDP) (32ms)
  ✓ MX records: (none - no mail servers configured)
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

## Changelog

### Recent Improvements
- 🔧 **Fixed IPv6 ping issues** - IPv6 ICMP now works correctly on macOS
- 🛡️ **Enhanced DNS security** - Added sinkhole detection and improved error handling  
- 📦 **Updated dependencies** - Migrated from trust-dns to hickory-dns for better maintenance
- 🎯 **Improved accuracy** - Fixed DNS search domain issues for more accurate testing
- ⚡ **Better performance** - Async implementation with proper timeout handling
