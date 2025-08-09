use crate::network::IpVersion;
use crate::utils::{measure_time, NetworkError, Result, TestResult};
use std::time::Duration;

pub struct MtuDiscovery {
    pub target: String,
    pub ip_version: IpVersion,
    pub timeout: Duration,
    pub max_mtu: u16,
    pub min_mtu: u16,
}

impl Default for MtuDiscovery {
    fn default() -> Self {
        Self {
            target: String::new(),
            ip_version: IpVersion::V4,
            timeout: Duration::from_secs(5),
            max_mtu: 1500,
            min_mtu: 68,
        }
    }
}

impl MtuDiscovery {
    pub fn new(target: String, ip_version: IpVersion) -> Self {
        Self {
            target,
            ip_version,
            ..Default::default()
        }
    }

    pub fn with_range(mut self, min_mtu: u16, max_mtu: u16) -> Self {
        self.min_mtu = min_mtu;
        self.max_mtu = max_mtu;
        self
    }

    pub async fn discover(&self) -> TestResult {
        let test_name = format!("MTU discovery for {} ({:?})", self.target, self.ip_version);

        let (duration, result) = measure_time(|| async { self.binary_search_mtu().await }).await;

        match result {
            Ok(mtu) => TestResult::new(test_name)
                .success(duration, format!("Discovered MTU: {} bytes", mtu)),
            Err(error) => TestResult::new(test_name).failure(duration, error),
        }
    }

    async fn binary_search_mtu(&self) -> Result<u16> {
        let mut low = self.min_mtu;
        let mut high = self.max_mtu;
        let mut best_mtu = low;

        while low <= high {
            let mid = (low + high) / 2;

            match self.test_mtu_size(mid).await {
                Ok(_) => {
                    best_mtu = mid;
                    low = mid + 1;
                }
                Err(_) => {
                    high = mid - 1;
                }
            }
        }

        Ok(best_mtu)
    }

    async fn test_mtu_size(&self, mtu_size: u16) -> Result<()> {
        // Use system ping with packet size for MTU testing
        let ping_cmd = match self.ip_version {
            IpVersion::V4 => "ping",
            IpVersion::V6 => "ping6",
        };

        let payload_size = match self.ip_version {
            IpVersion::V4 => mtu_size.saturating_sub(28), // IP header 20 + ICMP header 8
            IpVersion::V6 => mtu_size.saturating_sub(48), // IPv6 header 40 + ICMP header 8
        };

        if payload_size < 8 {
            return Err(NetworkError::InvalidMtu(mtu_size));
        }

        let output = tokio::process::Command::new(ping_cmd)
            .args(&[
                "-c",
                "1",
                "-W",
                "5000",
                "-M",
                "do", // Don't fragment
                "-s",
                &payload_size.to_string(),
                &self.target,
            ])
            .output()
            .await
            .map_err(|e| NetworkError::Io(e))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(NetworkError::Other("MTU test failed".to_string()))
        }
    }
}

pub async fn test_common_mtu_sizes(target: &str, ip_version: IpVersion) -> Vec<TestResult> {
    let common_sizes = [68, 576, 1280, 1500, 4464, 9000];
    let mut results = Vec::new();

    for &size in &common_sizes {
        let discovery = MtuDiscovery::new(target.to_string(), ip_version).with_range(size, size);

        let mut result = discovery.discover().await;
        result.test_name = format!("MTU test {} bytes for {} ({:?})", size, target, ip_version);
        results.push(result);
    }

    results
}

pub async fn full_mtu_discovery(target: &str, ip_version: IpVersion) -> TestResult {
    let discovery = MtuDiscovery::new(target.to_string(), ip_version);
    discovery.discover().await
}
