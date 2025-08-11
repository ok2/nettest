//! # `NetTest` - Comprehensive Network Testing Library
//!
//! `NetTest` is a powerful Rust library for network connectivity and DNS testing with comprehensive
//! capabilities for diagnosing network issues, analyzing DNS infrastructure, and discovering
//! network path characteristics.
//!
//! ## Features
//!
//! - **🌐 Network Connectivity Testing**: TCP, UDP, and ICMP ping tests with IPv4/IPv6 support
//! - **🔍 DNS Resolution Testing**: Comprehensive DNS testing with 23 traditional DNS servers  
//! - **🚀 DNS-over-HTTPS (`DoH`) Support**: 16 `DoH` providers with JSON and Wire format support
//! - **📏 MTU Discovery**: Automated MTU path discovery and common size testing
//! - **🛡️ Security Analysis**: DNS filtering, sinkhole detection, and security categorization
//! - **⚡ High Performance**: Async/concurrent testing with progress indicators
//! - **📊 Multiple Output Formats**: Human-readable and JSON output formats
//!
//! ## Quick Start
//!
//! ### DNS Testing
//! ```rust
//! use nettest::dns::DnsTest;
//! use hickory_client::rr::RecordType;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Basic DNS query
//!     let test = DnsTest::new("google.com".to_string(), RecordType::A);
//!     let result = test.run().await;
//!     
//!     if result.success {
//!         println!("DNS resolution successful: {}", result.details);
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ### DNS-over-HTTPS Testing
//! ```rust
//! use nettest::dns::doh::{DohTest, DOH_PROVIDERS};
//! use hickory_client::rr::RecordType;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Test with Google DoH provider
//!     let provider = DOH_PROVIDERS[0].clone();
//!     let test = DohTest::new("example.com".to_string(), RecordType::A, provider);
//!     let result = test.run().await;
//!     
//!     println!("DoH test result: {}", result.test_name);
//!     Ok(())
//! }
//! ```
//!
//! ### Network Connectivity Testing
//! ```rust
//! use nettest::network::{NetworkTest, IpVersion, NetworkProtocol};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // TCP connectivity test
//!     let test = NetworkTest::new("google.com".to_string(), IpVersion::V4, NetworkProtocol::Tcp)
//!         .with_port(80);
//!     let result = test.run().await;
//!     
//!     if result.success {
//!         println!("TCP connection successful: {}", result.details);
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ### MTU Discovery
//! ```rust
//! use nettest::mtu::MtuDiscovery;
//! use nettest::network::IpVersion;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Discover MTU size
//!     let discovery = MtuDiscovery::new("cloudflare.com".to_string(), IpVersion::V4);
//!     let result = discovery.discover().await;
//!     
//!     if result.success {
//!         println!("MTU discovery: {}", result.details);
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ### Comprehensive DNS Server Testing
//! ```rust
//! use nettest::dns::test_common_dns_servers;
//! use hickory_client::rr::RecordType;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Test all 39 DNS providers (23 traditional + 16 DoH)
//!     let results = test_common_dns_servers("example.com", RecordType::A).await;
//!     
//!     let successful = results.iter().filter(|r| r.success).count();
//!     let total = results.len();
//!     
//!     println!("DNS server tests: {}/{} successful", successful, total);
//!     
//!     for result in &results {
//!         if result.success {
//!             println!("✓ {}: {}", result.test_name, result.details);
//!         } else {
//!             println!("✗ {}: {:?}", result.test_name, result.error);
//!         }
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Advanced Usage
//!
//! ### Custom DNS Server Testing
//! ```rust
//! use nettest::dns::DnsTest;
//! use hickory_client::rr::RecordType;
//! use std::net::SocketAddr;
//! use std::str::FromStr;
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let custom_server = SocketAddr::from_str("1.1.1.1:53")?;
//!     
//!     let test = DnsTest::new("example.com".to_string(), RecordType::TXT)
//!         .with_server(custom_server)
//!         .with_timeout(Duration::from_secs(10))
//!         .with_tcp(true);
//!     
//!     let result = test.run().await;
//!     println!("Custom DNS server test: {}", result.test_name);
//!
//!     Ok(())
//! }
//! ```
//!
//! ### Security Analysis
//! ```rust
//! use nettest::dns::DnsTest;
//! use hickory_client::rr::RecordType;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Test potentially malicious domain
//!     let test = DnsTest::new("suspicious-domain.test".to_string(), RecordType::A);
//!     let result = test.run_security_test().await;
//!     
//!     if result.success && result.details.contains("BLOCKED") {
//!         println!("Domain successfully blocked by security filters");
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## DNS Providers
//!
//! `NetTest` supports testing against 39 total DNS providers:
//!
//! ### Traditional DNS Servers (23 providers)
//! - **Google DNS**: 8.8.8.8, 8.8.4.4  
//! - **Cloudflare DNS**: 1.1.1.1, 1.0.0.1, 1.1.1.2 (family), 1.1.1.3 (security)
//! - **Quad9**: 9.9.9.9 (secure), 9.9.9.10 (unsecured), 9.9.9.11 (ECS)
//! - **OpenDNS**: Standard and `FamilyShield` variants
//! - **`AdGuard` DNS**: Standard, Family, and Unfiltered variants
//!
//! ### DNS-over-HTTPS Providers (16 providers)
//! - **Google**: Wire format and JSON API support
//! - **Cloudflare**: All variants with both JSON and Wire format
//! - **Quad9**: Secure, Unsecured, and ECS variants
//! - **OpenDNS**: Standard and Family Shield
//! - **`AdGuard`**: All filtering variants
//!
//! ## Performance Characteristics
//!
//! - **DNS Queries**: 5-50ms for traditional DNS, 50-200ms for `DoH`
//! - **Concurrent Testing**: Up to 39 simultaneous DNS provider tests
//! - **Large DNS Responses**: Automatic EDNS0 support for TXT records
//! - **MTU Discovery**: Binary search algorithm for efficient path MTU discovery
//!
//! ## Error Handling
//!
//! `NetTest` provides comprehensive error handling with detailed error messages:
//!
//! ```rust
//! use nettest::utils::NetworkError;
//! use nettest::dns::DnsTest;
//! use hickory_client::rr::RecordType;
//!
//! #[tokio::main]
//! async fn main() {
//!     let test = DnsTest::new("nonexistent.invalid".to_string(), RecordType::A);
//!     let result = test.run().await;
//!     
//!     match result.error {
//!         Some(NetworkError::DnsResolution(msg)) => {
//!             println!("DNS resolution failed: {}", msg);
//!         },
//!         Some(NetworkError::Timeout) => {
//!             println!("Request timed out");
//!         },
//!         Some(NetworkError::Io(err)) => {
//!             println!("I/O error: {}", err);
//!         },
//!         _ => {}
//!     }
//! }
//! ```

pub mod cli;
pub mod dns;
pub mod mtu;
pub mod network;
pub mod utils;

pub use cli::*;
pub use dns::*;
pub use mtu::*;
pub use network::*;
pub use utils::*;
