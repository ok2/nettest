use super::{IpVersion, NetworkTest};
use crate::utils::{NetworkError, Result, TestResult};
use tokio::time::Duration;

impl NetworkTest {
    pub async fn test_icmp(&self) -> Result<String> {
        // Use system ping command for simplicity and compatibility
        let target = &self.target;

        let ping_cmd = match self.ip_version {
            IpVersion::V4 => "ping",
            IpVersion::V6 => "ping6",
        };

        let output = tokio::process::Command::new(ping_cmd)
            .args(&["-c", "1", "-W", "5000", target]) // 1 ping, 5 second timeout
            .output()
            .await
            .map_err(|e| NetworkError::Io(e))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(line) = stdout.lines().find(|line| line.contains("time=")) {
                Ok(format!("ICMP ping successful: {}", line.trim()))
            } else {
                Ok("ICMP ping successful".to_string())
            }
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(NetworkError::Other(format!("Ping failed: {}", stderr)))
        }
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
