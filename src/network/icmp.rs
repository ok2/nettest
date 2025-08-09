use super::{IpVersion, NetworkTest};
use crate::utils::{NetworkError, Result, TestResult};
use std::net::ToSocketAddrs;
use tokio::time::Duration;

impl NetworkTest {
    pub async fn test_icmp(&self) -> Result<String> {
        // Resolve the target to an IP address first
        let target_ip = self.resolve_target_to_ip().await?;

        let ping_cmd = match self.ip_version {
            IpVersion::V4 => "ping",
            IpVersion::V6 => "ping6",
        };

        let mut cmd = tokio::process::Command::new(ping_cmd);
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

pub async fn ping_test(target: &str, ip_version: IpVersion, count: u32) -> Vec<TestResult> {
    let mut results = Vec::new();

    for i in 0..count {
        let test = NetworkTest::new(target.to_string(), ip_version, super::NetworkProtocol::Icmp);

        let mut result = test.run().await;
        result.test_name = format!("ICMP ping #{} to {} ({:?})", i + 1, target, ip_version);
        results.push(result);

        if i < count - 1 {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    results
}
