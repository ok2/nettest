//! ICMP ping testing module.
//!
//! This module provides ICMP ping testing capabilities with IPv4/IPv6 support and
//! optional sudo privileges for more accurate testing results.
//!
//! # Examples
//!
//! ## Basic ICMP Ping
//! ```rust
//! use nettest::network::{NetworkTest, IpVersion, NetworkProtocol};
//!
//! #[tokio::main]
//! async fn main() {
//!     let test = NetworkTest::new("google.com".to_string(), IpVersion::V4, NetworkProtocol::Icmp);
//!     let result = test.test_icmp().await;
//!     
//!     match result {
//!         Ok(details) => println!("Ping successful: {}", details),
//!         Err(error) => println!("Ping failed: {}", error),
//!     }
//! }
//! ```
//!
//! ## Multiple Ping Tests
//! ```rust
//! use nettest::network::{ping_test, IpVersion};
//!
//! #[tokio::main]
//! async fn main() {
//!     let results = ping_test("cloudflare.com", IpVersion::V4, 5).await;
//!     
//!     let successful = results.iter().filter(|r| r.success).count();
//!     println!("Ping results: {}/{} successful", successful, results.len());
//! }
//! ```

use super::{IpVersion, NetworkTest};
use crate::utils::{NetworkError, Result, TestResult};
use std::net::ToSocketAddrs;
use tokio::time::Duration;

impl NetworkTest {
    /// Tests ICMP connectivity without sudo privileges.
    ///
    /// This is a convenience method that calls `test_icmp_with_sudo(false)`.
    /// On some systems, ICMP may require elevated privileges for accurate results.
    ///
    /// # Returns
    /// A `Result<String>` containing ping details on success or an error on failure.
    ///
    /// # Examples
    /// ```rust
    /// use nettest::network::{NetworkTest, IpVersion, NetworkProtocol};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let test = NetworkTest::new("8.8.8.8".to_string(), IpVersion::V4, NetworkProtocol::Icmp);
    ///     
    ///     match test.test_icmp().await {
    ///         Ok(result) => println!("Ping result: {}", result),
    ///         Err(error) => println!("Ping error: {}", error),
    ///     }
    /// }
    /// ```
    pub async fn test_icmp(&self) -> Result<String> {
        self.test_icmp_with_sudo(false).await
    }

    /// Tests ICMP connectivity with optional sudo privileges.
    ///
    /// This method performs ICMP ping tests with the option to use sudo for more accurate
    /// results. Sudo privileges can provide better timing accuracy and may be required
    /// on some systems for ICMP socket operations.
    ///
    /// # Arguments
    /// * `use_sudo` - Whether to use sudo for the ping command
    ///
    /// # Returns
    /// A `Result<String>` containing detailed ping information on success
    ///
    /// # Examples
    /// ```rust
    /// use nettest::network::{NetworkTest, IpVersion, NetworkProtocol};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let test = NetworkTest::new("google.com".to_string(), IpVersion::V4, NetworkProtocol::Icmp);
    ///     
    ///     // Test without sudo (may have limitations)
    ///     let normal_result = test.test_icmp_with_sudo(false).await;
    ///     
    ///     // Test with sudo (requires password prompt, more accurate)
    ///     let sudo_result = test.test_icmp_with_sudo(true).await;
    ///     
    ///     match sudo_result {
    ///         Ok(details) => println!("Sudo ping result: {}", details),
    ///         Err(error) => println!("Sudo ping failed: {}", error),
    ///     }
    /// }
    /// ```
    pub async fn test_icmp_with_sudo(&self, use_sudo: bool) -> Result<String> {
        // Resolve the target to an IP address first
        let target_ip = self.resolve_target_to_ip().await?;

        let ping_cmd = match self.ip_version {
            IpVersion::V4 => "ping",
            IpVersion::V6 => "ping6",
        };

        let mut cmd = if use_sudo {
            let mut sudo_cmd = tokio::process::Command::new("sudo");
            sudo_cmd.arg(ping_cmd);
            sudo_cmd
        } else {
            tokio::process::Command::new(ping_cmd)
        };
        cmd.args(&["-c", "1"]);

        // Add timeout for IPv4 ping, but not for ping6 on macOS (it uses different syntax)
        match self.ip_version {
            IpVersion::V4 => {
                cmd.args(&["-W", "5000"]); // 5 second timeout for IPv4
            }
            IpVersion::V6 => {
                // ping6 on macOS doesn't support -W flag in the same way
                // We'll rely on Tokio's timeout wrapper instead
            }
        }

        cmd.arg(&target_ip);

        let output = tokio::time::timeout(Duration::from_secs(5), cmd.output())
            .await
            .map_err(|_| NetworkError::Timeout)?
            .map_err(|e| NetworkError::Io(e))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(line) = stdout.lines().find(|line| line.contains("time=")) {
                Ok(format!(
                    "ICMP ping to {} ({}): {}",
                    self.target,
                    target_ip,
                    line.trim()
                ))
            } else {
                Ok(format!(
                    "ICMP ping to {} ({}) successful",
                    self.target, target_ip
                ))
            }
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(NetworkError::Other(format!(
                "Ping to {} ({}) failed: {}",
                self.target, target_ip, stderr
            )))
        }
    }

    async fn resolve_target_to_ip(&self) -> Result<String> {
        // Try to parse as IP address first
        if let Ok(ip) = self.target.parse::<std::net::IpAddr>() {
            return match (ip, self.ip_version) {
                (std::net::IpAddr::V4(_), IpVersion::V4) => Ok(self.target.clone()),
                (std::net::IpAddr::V6(_), IpVersion::V6) => Ok(self.target.clone()),
                _ => Err(NetworkError::Other(format!(
                    "IP version mismatch: {} is not {:?}",
                    ip, self.ip_version
                ))),
            };
        }

        // Resolve domain name
        let socket_addrs: Vec<_> = tokio::task::spawn_blocking({
            let target = self.target.clone();
            move || {
                format!("{}:80", target)
                    .to_socket_addrs()
                    .map_err(|e| {
                        NetworkError::DnsResolution(format!("Failed to resolve {}: {}", target, e))
                    })
                    .map(|addrs| addrs.collect::<Vec<_>>())
            }
        })
        .await
        .map_err(|e| NetworkError::Other(format!("Task join error: {}", e)))??;

        // Find the first matching IP version
        for addr in socket_addrs {
            match (addr.ip(), self.ip_version) {
                (std::net::IpAddr::V4(ipv4), IpVersion::V4) => return Ok(ipv4.to_string()),
                (std::net::IpAddr::V6(ipv6), IpVersion::V6) => return Ok(ipv6.to_string()),
                _ => continue,
            }
        }

        Err(NetworkError::DnsResolution(format!(
            "No {:?} address found for {}",
            self.ip_version, self.target
        )))
    }
}

/// Performs multiple ping tests to a target.
///
/// This is a convenience function that performs multiple ping tests without sudo privileges.
/// It calls `ping_test_with_sudo` with `use_sudo = false`.
///
/// # Arguments
/// * `target` - The target hostname or IP address
/// * `ip_version` - The IP version to use (V4 or V6)
/// * `count` - Number of ping tests to perform
///
/// # Returns
/// A vector of `TestResult` containing results from each ping test
///
/// # Examples
/// ```rust
/// use nettest::network::{ping_test, IpVersion};
///
/// #[tokio::main]
/// async fn main() {
///     let results = ping_test("8.8.8.8", IpVersion::V4, 3).await;
///     
///     assert_eq!(results.len(), 3);
///     
///     let successful = results.iter().filter(|r| r.success).count();
///     println!("Ping tests: {}/{} successful", successful, results.len());
///     
///     // Check first result
///     if let Some(first_result) = results.first() {
///         assert!(first_result.test_name.contains("ICMP ping #1"));
///         assert!(first_result.test_name.contains("8.8.8.8"));
///     }
/// }
/// ```
pub async fn ping_test(target: &str, ip_version: IpVersion, count: u32) -> Vec<TestResult> {
    ping_test_with_sudo(target, ip_version, count, false).await
}

/// Performs multiple ping tests with optional sudo privileges.
///
/// This function performs a series of ping tests with a 1-second delay between each test.
/// Using sudo can provide more accurate timing and may be required on some systems.
///
/// # Arguments
/// * `target` - The target hostname or IP address
/// * `ip_version` - The IP version to use (V4 or V6)
/// * `count` - Number of ping tests to perform
/// * `use_sudo` - Whether to use sudo for more accurate results
///
/// # Returns
/// A vector of `TestResult` containing results from each ping test
///
/// # Examples
/// ```rust
/// use nettest::network::{ping_test_with_sudo, IpVersion};
///
/// #[tokio::main]
/// async fn main() {
///     // Test with regular privileges
///     let normal_results = ping_test_with_sudo("google.com", IpVersion::V4, 2, false).await;
///     
///     // Test with sudo (requires password prompt)
///     let sudo_results = ping_test_with_sudo("google.com", IpVersion::V4, 2, true).await;
///     
///     assert_eq!(normal_results.len(), 2);
///     assert_eq!(sudo_results.len(), 2);
///     
///     // Check test naming
///     if let Some(first) = normal_results.first() {
///         assert!(first.test_name.contains("ICMP ping #1"));
///         assert!(first.test_name.contains("google.com"));
///     }
/// }
/// ```
pub async fn ping_test_with_sudo(
    target: &str,
    ip_version: IpVersion,
    count: u32,
    use_sudo: bool,
) -> Vec<TestResult> {
    let mut results = Vec::new();

    for i in 0..count {
        let test = NetworkTest::new(target.to_string(), ip_version, super::NetworkProtocol::Icmp);

        let result = if use_sudo {
            let start = std::time::Instant::now();
            let icmp_result = test.test_icmp_with_sudo(use_sudo).await;
            let duration = start.elapsed();

            match icmp_result {
                Ok(details) => crate::utils::TestResult::new(format!(
                    "ICMP ping #{} to {} ({:?})",
                    i + 1,
                    target,
                    ip_version
                ))
                .success(duration, details),
                Err(error) => crate::utils::TestResult::new(format!(
                    "ICMP ping #{} to {} ({:?})",
                    i + 1,
                    target,
                    ip_version
                ))
                .failure(duration, error),
            }
        } else {
            let mut result = test.run().await;
            result.test_name = format!("ICMP ping #{} to {} ({:?})", i + 1, target, ip_version);
            result
        };

        results.push(result);

        if i < count - 1 {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    results
}
