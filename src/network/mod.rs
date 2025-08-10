use crate::utils::{measure_time, NetworkError, Result, TestResult};
use std::net::IpAddr;
use std::time::Duration;

pub mod icmp;
pub mod tcp;
pub mod udp;

pub use icmp::*;
pub use tcp::*;
pub use udp::*;

#[derive(Debug, Clone, Copy)]
pub enum IpVersion {
    V4,
    V6,
}

#[derive(Debug, Clone, Copy)]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone)]
pub struct NetworkTest {
    pub target: String,
    pub ip_version: IpVersion,
    pub protocol: NetworkProtocol,
    pub port: Option<u16>,
    pub timeout: Duration,
}

impl NetworkTest {
    pub fn new(target: String, ip_version: IpVersion, protocol: NetworkProtocol) -> Self {
        Self {
            target,
            ip_version,
            protocol,
            port: None,
            timeout: Duration::from_secs(5),
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub async fn run(&self) -> TestResult {
        let test_name = format!(
            "{:?} test to {} {:?} {}",
            self.protocol,
            self.target,
            self.ip_version,
            self.port.map(|p| format!(":{}", p)).unwrap_or_default()
        );

        let (duration, result) = measure_time(|| async {
            match self.protocol {
                NetworkProtocol::Tcp => self.test_tcp().await,
                NetworkProtocol::Udp => self.test_udp().await,
                NetworkProtocol::Icmp => self.test_icmp().await,
            }
        })
        .await;

        match result {
            Ok(details) => TestResult::new(test_name).success(duration, details),
            Err(error) => TestResult::new(test_name).failure(duration, error),
        }
    }

    async fn resolve_target(&self) -> Result<IpAddr> {
        use hickory_resolver::config::*;
        use hickory_resolver::TokioAsyncResolver;

        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        let lookup = match self.ip_version {
            IpVersion::V4 => {
                let response = resolver
                    .ipv4_lookup(&self.target)
                    .await
                    .map_err(|e| NetworkError::DnsResolution(e.to_string()))?;
                response.iter().next().map(|ip| IpAddr::V4(**ip))
            }
            IpVersion::V6 => {
                let response = resolver
                    .ipv6_lookup(&self.target)
                    .await
                    .map_err(|e| NetworkError::DnsResolution(e.to_string()))?;
                response.iter().next().map(|ip| IpAddr::V6(**ip))
            }
        };

        lookup.ok_or_else(|| NetworkError::DnsResolution("No IP found".to_string()))
    }
}
