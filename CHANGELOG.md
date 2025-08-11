# Changelog

All notable changes to the NetTest project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive documentation with extensive doctests
- Integration test examples demonstrating all major features
- Enhanced README with detailed usage examples
- Library-level documentation in src/lib.rs
- Cargo.toml metadata for docs.rs integration

### Changed
- Improved API documentation with real-world examples
- Enhanced error messages and debugging information

## [0.1.0] - 2024-01-15

### Added
- **DNS Testing**
  - Comprehensive DNS resolution testing with multiple record types
  - Support for 23 traditional DNS servers including Google, Cloudflare, Quad9, OpenDNS, AdGuard
  - System DNS resolver integration with EDNS0 support
  - DNS sinkhole detection and security analysis
  - Smart error handling distinguishing between failures and missing records
  - Support for A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, and DNSSEC record types

- **DNS-over-HTTPS (DoH) Support**
  - 16 DoH providers with comprehensive coverage
  - Support for both JSON and Wire format protocols (RFC 8484)
  - Provider variants for security filtering (malware blocking, family filters)
  - Automatic format detection and provider-specific optimizations
  - Google, Cloudflare, Quad9, OpenDNS, and AdGuard DoH endpoints

- **Network Connectivity Testing**
  - TCP and UDP connection testing with IPv4/IPv6 support
  - ICMP ping tests with optional sudo privileges
  - Common port scanning functionality
  - Configurable timeouts and retry logic
  - Cross-platform compatibility (macOS, Linux, Windows)

- **MTU Discovery**
  - Binary search MTU path discovery algorithm  
  - Common MTU size testing (68, 576, 1280, 1492, 1500, 4464, 9000)
  - Custom MTU range testing capabilities
  - IPv6-aware MTU validation (1280 byte minimum)
  - Optional sudo support for accurate ICMP-based discovery

- **Security Analysis**
  - DNS filtering effectiveness analysis
  - Domain category testing (normal, ads, spam, adult, malicious, social, streaming, gaming, news)
  - Sinkhole IP detection (0.0.0.0, 127.x.x.x, common filtering IPs)
  - Security-focused DNS provider testing

- **CLI Interface**
  - Comprehensive command-line interface with subcommands
  - Human-readable output with colored formatting
  - JSON output format for integration with other tools
  - Progress indicators for long-running operations
  - Verbose logging support

- **Performance Features**
  - Async/concurrent testing architecture
  - Parallel DNS provider testing (up to 39 simultaneous queries)
  - Efficient binary search algorithms for MTU discovery
  - Connection pooling and timeout optimization
  - EDNS0 support for large DNS responses

### Technical Details
- **Dependencies**: Built with Tokio for async networking, Hickory DNS for resolution, Reqwest for HTTP
- **Architecture**: Modular design with separate modules for DNS, network, MTU, and utilities
- **Error Handling**: Comprehensive error types with detailed error messages
- **Testing**: Extensive test suite with unit tests, integration tests, and doctests
- **Documentation**: Complete API documentation with examples and usage patterns

### Performance Benchmarks
- DNS queries: 5-50ms for traditional DNS, 50-200ms for DoH
- MTU discovery: Binary search completes in < 10 iterations for typical ranges
- Concurrent testing: 39 DNS providers tested simultaneously
- Memory usage: Efficient async implementation with minimal resource usage

### Compatibility
- **Rust Version**: 1.70+ required
- **Platforms**: macOS, Linux, Windows
- **IPv6**: Full IPv6 support alongside IPv4
- **Privileges**: Optional sudo support for enhanced ICMP and MTU testing

### Known Limitations
- ICMP ping may require elevated privileges on some systems
- MTU discovery accuracy depends on network path characteristics
- Some DoH providers may have rate limiting
- IPv6 connectivity depends on network infrastructure support