use super::{IpVersion, NetworkTest};
use crate::utils::{NetworkError, Result, TestResult};
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::time::timeout;

impl NetworkTest {
    pub async fn test_tcp(&self) -> Result<String> {
        let ip = self.resolve_target().await?;
        let port = self.port.unwrap_or(80);
        let addr = SocketAddr::new(ip, port);

        let stream = timeout(self.timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| NetworkError::Timeout)?
            .map_err(|e| NetworkError::Io(e))?;

        let local_addr = stream.local_addr().map_err(NetworkError::Io)?;
        let peer_addr = stream.peer_addr().map_err(NetworkError::Io)?;

        Ok(format!(
            "TCP connection successful: {} -> {}",
            local_addr, peer_addr
        ))
    }
}

pub async fn test_tcp_ports(target: &str, ports: &[u16], ip_version: IpVersion) -> Vec<TestResult> {
    let mut results = Vec::new();

    for &port in ports {
        let test = NetworkTest::new(target.to_string(), ip_version, super::NetworkProtocol::Tcp)
            .with_port(port);
        results.push(test.run().await);
    }

    results
}

pub async fn test_tcp_common_ports(target: &str, ip_version: IpVersion) -> Vec<TestResult> {
    let common_ports = [22, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443];
    test_tcp_ports(target, &common_ports, ip_version).await
}
