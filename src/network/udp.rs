use super::{IpVersion, NetworkTest};
use crate::utils::{NetworkError, Result, TestResult};
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::timeout;

impl NetworkTest {
    pub async fn test_udp(&self) -> Result<String> {
        let ip = self.resolve_target().await?;
        let port = self.port.unwrap_or(53);
        let addr = SocketAddr::new(ip, port);

        let bind_addr = match self.ip_version {
            IpVersion::V4 => "0.0.0.0:0",
            IpVersion::V6 => "[::]:0",
        };

        let socket = UdpSocket::bind(bind_addr).await.map_err(NetworkError::Io)?;

        socket.connect(addr).await.map_err(NetworkError::Io)?;

        let test_data = b"test";

        let send_result = timeout(self.timeout, socket.send(test_data))
            .await
            .map_err(|_| NetworkError::Timeout)?
            .map_err(NetworkError::Io)?;

        let mut buf = [0; 1024];
        let recv_result =
            timeout(std::time::Duration::from_millis(100), socket.recv(&mut buf)).await;

        let details = match recv_result {
            Ok(Ok(bytes)) => format!(
                "UDP test successful: sent {} bytes, received {} bytes to {}",
                send_result, bytes, addr
            ),
            _ => format!(
                "UDP test (send only): sent {} bytes to {} (no response expected for basic connectivity test)",
                send_result, addr
            ),
        };

        Ok(details)
    }
}

pub async fn test_udp_ports(target: &str, ports: &[u16], ip_version: IpVersion) -> Vec<TestResult> {
    let mut results = Vec::new();

    for &port in ports {
        let test = NetworkTest::new(target.to_string(), ip_version, super::NetworkProtocol::Udp)
            .with_port(port);
        results.push(test.run().await);
    }

    results
}

pub async fn test_udp_common_ports(target: &str, ip_version: IpVersion) -> Vec<TestResult> {
    let common_ports = [53, 67, 68, 123, 161, 162, 514, 1194, 5353];
    test_udp_ports(target, &common_ports, ip_version).await
}
