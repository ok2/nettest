use crate::utils::{measure_time, NetworkError, Result, TestResult};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use trust_dns_client::rr::{Name, RData, RecordData, RecordType};
use trust_dns_resolver::config::*;
use trust_dns_resolver::system_conf;
use trust_dns_resolver::TokioAsyncResolver;

pub mod categories;
pub mod queries;

pub use categories::*;
pub use queries::*;

#[derive(Debug, Clone)]
pub enum ConnectivityStatus {
    Reachable,
    DnsOnlyNetworkBlocked,
    PartiallyReachable,
}

#[derive(Debug, Clone)]
pub struct DnsTest {
    pub domain: String,
    pub record_type: RecordType,
    pub server: Option<SocketAddr>,
    pub timeout: Duration,
    pub use_tcp: bool,
}

impl DnsTest {
    pub fn new(domain: String, record_type: RecordType) -> Self {
        Self {
            domain,
            record_type,
            server: None,
            timeout: Duration::from_secs(5),
            use_tcp: false,
        }
    }

    pub fn with_server(mut self, server: SocketAddr) -> Self {
        self.server = Some(server);
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_tcp(mut self, use_tcp: bool) -> Self {
        self.use_tcp = use_tcp;
        self
    }

    pub async fn run(&self) -> TestResult {
        let protocol = if self.use_tcp { "TCP" } else { "UDP" };
        let server_info = self
            .server
            .map(|s| format!(" via {}", s))
            .unwrap_or_default();

        let test_name = format!(
            "DNS {:?} query for {} ({}{})",
            self.record_type, self.domain, protocol, server_info
        );

        let (duration, result) = measure_time(|| async {
            if let Some(server) = self.server {
                self.query_specific_server(server).await
            } else {
                self.query_system_resolver().await
            }
        })
        .await;

        match result {
            Ok(details) => TestResult::new(test_name).success(duration, details),
            Err(error) => TestResult::new(test_name).failure(duration, error),
        }
    }

    pub async fn run_security_test(&self) -> TestResult {
        let protocol = if self.use_tcp { "TCP" } else { "UDP" };
        let server_info = self
            .server
            .map(|s| format!(" via {}", s))
            .unwrap_or_default();

        let test_name = format!(
            "DNS {:?} query for {} ({}{})",
            self.record_type, self.domain, protocol, server_info
        );

        let (duration, result) = measure_time(|| async {
            if let Some(server) = self.server {
                self.query_specific_server(server).await
            } else {
                self.query_system_resolver().await
            }
        })
        .await;

        match result {
            Ok(details) => {
                // Check if the resolved IPs are sinkholed
                let ips = self.extract_ips_from_dns_details(&details);
                let sinkhole_analysis = analyze_sinkhole_ips(&ips);

                match sinkhole_analysis {
                    SinkholeAnalysis::FullySinkholed(sinkhole_ips) => {
                        let sinkhole_list: Vec<String> =
                            sinkhole_ips.iter().map(|ip| ip.to_string()).collect();
                        TestResult::new(test_name).success(
                            duration,
                            format!(
                                "🕳️ SINKHOLED (security success): Redirected to sinkhole IPs: {}",
                                sinkhole_list.join(", ")
                            ),
                        )
                    }
                    SinkholeAnalysis::PartiallySinkholed {
                        sinkhole_ips,
                        legitimate_ips,
                    } => {
                        let sinkhole_list: Vec<String> =
                            sinkhole_ips.iter().map(|ip| ip.to_string()).collect();
                        let legit_list: Vec<String> =
                            legitimate_ips.iter().map(|ip| ip.to_string()).collect();
                        TestResult::new(test_name).success(
                            duration,
                            format!("⚠️ MIXED RESOLUTION: Sinkholed: {} | Real IPs: {} (partial security concern)", 
                                sinkhole_list.join(", "), legit_list.join(", "))
                        )
                    }
                    SinkholeAnalysis::NotSinkholed(_) => TestResult::new(test_name).success(
                        duration,
                        format!("⚠️ RESOLVED (potential security concern): {}", details),
                    ),
                }
            }
            Err(error) => {
                // For security tests, DNS resolution failures are considered successes
                match error {
                    NetworkError::DnsResolution(err_msg) => {
                        let blocking_explanation = analyze_dns_blocking(&err_msg);
                        TestResult::new(test_name).success(
                            duration,
                            format!("🛡️  BLOCKED (security success): {}", blocking_explanation),
                        )
                    }
                    _ => TestResult::new(test_name).failure(duration, error),
                }
            }
        }
    }

    pub async fn run_filtering_test(&self) -> TestResult {
        let protocol = if self.use_tcp { "TCP" } else { "UDP" };
        let server_info = self
            .server
            .map(|s| format!(" via {}", s))
            .unwrap_or_default();

        let test_name = format!(
            "DNS {:?} query for {} ({}{})",
            self.record_type, self.domain, protocol, server_info
        );

        let (duration, result) = measure_time(|| async {
            if let Some(server) = self.server {
                self.query_specific_server(server).await
            } else {
                self.query_system_resolver().await
            }
        })
        .await;

        match result {
            Ok(details) => {
                // Check if the resolved IPs are sinkholed
                let ips = self.extract_ips_from_dns_details(&details);
                let sinkhole_analysis = analyze_sinkhole_ips(&ips);

                match sinkhole_analysis {
                    SinkholeAnalysis::FullySinkholed(sinkhole_ips) => {
                        let sinkhole_list: Vec<String> =
                            sinkhole_ips.iter().map(|ip| ip.to_string()).collect();
                        TestResult::new(test_name).success(
                            duration,
                            format!("🕳️ SINKHOLED: Redirected to sinkhole IPs: {} (filtered via DNS redirect)", sinkhole_list.join(", "))
                        )
                    }
                    SinkholeAnalysis::PartiallySinkholed {
                        sinkhole_ips,
                        legitimate_ips,
                    } => {
                        let sinkhole_list: Vec<String> =
                            sinkhole_ips.iter().map(|ip| ip.to_string()).collect();
                        let legit_list: Vec<String> =
                            legitimate_ips.iter().map(|ip| ip.to_string()).collect();
                        TestResult::new(test_name).success(
                            duration,
                            format!("⚡ PARTIAL SINKHOLE: Sinkholed: {} | Real IPs: {} (partial filtering)", 
                                sinkhole_list.join(", "), legit_list.join(", "))
                        )
                    }
                    SinkholeAnalysis::NotSinkholed(_) => TestResult::new(test_name)
                        .success(duration, format!("📡 ACCESSIBLE: {}", details)),
                }
            }
            Err(error) => {
                // DNS resolution failed - for filtering tests, this is good (blocked)
                match error {
                    NetworkError::DnsResolution(err_msg) => {
                        let blocking_explanation = analyze_dns_blocking(&err_msg);
                        TestResult::new(test_name)
                            .success(duration, format!("🚫 FILTERED: {}", blocking_explanation))
                    }
                    _ => TestResult::new(test_name).failure(duration, error),
                }
            }
        }
    }

    pub async fn run_comprehensive_test(&self) -> TestResult {
        let protocol = if self.use_tcp { "TCP" } else { "UDP" };
        let server_info = self
            .server
            .map(|s| format!(" via {}", s))
            .unwrap_or_default();

        let test_name = format!(
            "DNS {:?} query for {} ({}{})",
            self.record_type, self.domain, protocol, server_info
        );

        let (dns_duration, dns_result) = measure_time(|| async {
            if let Some(server) = self.server {
                self.query_specific_server(server).await
            } else {
                self.query_system_resolver().await
            }
        })
        .await;

        match dns_result {
            Ok(dns_details) => {
                // DNS resolved, now check actual connectivity
                let connectivity_result =
                    self.check_connectivity_to_resolved_ips(&dns_details).await;
                let total_duration = dns_duration + Duration::from_millis(50); // Approximate connectivity check time

                match connectivity_result {
                    ConnectivityStatus::Reachable => {
                        TestResult::new(test_name).success(
                            total_duration,
                            format!("✅ FULLY ACCESSIBLE: {} | Connectivity: Reachable", dns_details)
                        )
                    }
                    ConnectivityStatus::DnsOnlyNetworkBlocked => {
                        TestResult::new(test_name).success(
                            total_duration,
                            format!("🌐 DNS RESOLVES, NETWORK BLOCKED: {} | Traffic blocked at ISP/router level", dns_details)
                        )
                    }
                    ConnectivityStatus::PartiallyReachable => {
                        TestResult::new(test_name).success(
                            total_duration,
                            format!("⚡ PARTIALLY REACHABLE: {} | Some ports blocked", dns_details)
                        )
                    }
                }
            }
            Err(error) => match error {
                NetworkError::DnsResolution(err_msg) => {
                    let blocking_explanation = analyze_dns_blocking(&err_msg);
                    TestResult::new(test_name).success(
                        dns_duration,
                        format!("🛡️ DNS BLOCKED: {}", blocking_explanation),
                    )
                }
                _ => TestResult::new(test_name).failure(dns_duration, error),
            },
        }
    }

    async fn query_system_resolver(&self) -> Result<String> {
        // Try to use system DNS configuration first, fall back to default if that fails
        let (config, opts) = match system_conf::read_system_conf() {
            Ok((config, opts)) => (config, opts),
            Err(_) => {
                // Fallback to default config if system config cannot be read
                eprintln!("Warning: Could not read system DNS config, using default");
                (ResolverConfig::default(), ResolverOpts::default())
            }
        };

        let resolver = TokioAsyncResolver::tokio(config, opts);

        let name = Name::from_str(&self.domain)
            .map_err(|e| NetworkError::DnsResolution(format!("Invalid domain: {}", e)))?;

        let response = timeout(self.timeout, async {
            match self.record_type {
                RecordType::A => {
                    let lookup = resolver
                        .ipv4_lookup(name.clone())
                        .await
                        .map_err(|e| format!("A lookup failed: {}", e))?;
                    let ips: Vec<String> = lookup.iter().map(|ip| ip.to_string()).collect();
                    Ok(format!("A records: {}", ips.join(", ")))
                }
                RecordType::AAAA => {
                    let lookup = resolver
                        .ipv6_lookup(name.clone())
                        .await
                        .map_err(|e| format!("AAAA lookup failed: {}", e))?;
                    let ips: Vec<String> = lookup.iter().map(|ip| ip.to_string()).collect();
                    Ok(format!("AAAA records: {}", ips.join(", ")))
                }
                RecordType::MX => {
                    let lookup = resolver
                        .mx_lookup(name.clone())
                        .await
                        .map_err(|e| format!("MX lookup failed: {}", e))?;
                    let records: Vec<String> = lookup
                        .iter()
                        .map(|mx| format!("{} {}", mx.preference(), mx.exchange()))
                        .collect();
                    Ok(format!("MX records: {}", records.join(", ")))
                }
                RecordType::TXT => {
                    let lookup = resolver
                        .txt_lookup(name.clone())
                        .await
                        .map_err(|e| format!("TXT lookup failed: {}", e))?;
                    let records: Vec<String> = lookup.iter().map(|txt| txt.to_string()).collect();
                    Ok(format!("TXT records: {}", records.join(", ")))
                }
                RecordType::NS => {
                    let lookup = resolver
                        .ns_lookup(name.clone())
                        .await
                        .map_err(|e| format!("NS lookup failed: {}", e))?;
                    let records: Vec<String> = lookup.iter().map(|ns| ns.to_string()).collect();
                    Ok(format!("NS records: {}", records.join(", ")))
                }
                RecordType::CNAME => {
                    let lookup = resolver
                        .lookup(name.clone(), self.record_type)
                        .await
                        .map_err(|e| format!("CNAME lookup failed: {}", e))?;
                    let records: Vec<String> = lookup
                        .iter()
                        .filter_map(|record| {
                            if let RData::CNAME(cname) = record.clone().into_rdata() {
                                Some(cname.to_string())
                            } else {
                                None
                            }
                        })
                        .collect();
                    Ok(format!("CNAME records: {}", records.join(", ")))
                }
                RecordType::SOA => {
                    let lookup = resolver
                        .soa_lookup(name.clone())
                        .await
                        .map_err(|e| format!("SOA lookup failed: {}", e))?;
                    let records: Vec<String> = lookup
                        .iter()
                        .map(|soa| {
                            format!(
                                "{} {} {} {} {} {} {}",
                                soa.mname(),
                                soa.rname(),
                                soa.serial(),
                                soa.refresh(),
                                soa.retry(),
                                soa.expire(),
                                soa.minimum()
                            )
                        })
                        .collect();
                    Ok(format!("SOA records: {}", records.join(", ")))
                }
                RecordType::PTR => {
                    let lookup = resolver
                        .lookup(name.clone(), self.record_type)
                        .await
                        .map_err(|e| format!("PTR lookup failed: {}", e))?;
                    let records: Vec<String> = lookup
                        .iter()
                        .filter_map(|record| {
                            if let RData::PTR(ptr) = record.clone().into_rdata() {
                                Some(ptr.to_string())
                            } else {
                                None
                            }
                        })
                        .collect();
                    Ok(format!("PTR records: {}", records.join(", ")))
                }
                _ => {
                    let lookup = resolver
                        .lookup(name.clone(), self.record_type)
                        .await
                        .map_err(|e| format!("Lookup failed: {}", e))?;
                    let count = lookup.iter().count();
                    Ok(format!("{:?} records: {} found", self.record_type, count))
                }
            }
        })
        .await
        .map_err(|_| NetworkError::Timeout)?
        .map_err(|_: String| NetworkError::DnsResolution("System resolver failed".to_string()))?;

        Ok(response)
    }

    async fn query_specific_server(&self, server: SocketAddr) -> Result<String> {
        // Create a resolver configuration that uses the specific server
        let mut config = ResolverConfig::new();
        config.add_name_server(trust_dns_resolver::config::NameServerConfig::new(
            server,
            trust_dns_resolver::config::Protocol::Udp,
        ));
        let opts = ResolverOpts::default();

        let resolver = TokioAsyncResolver::tokio(config, opts);

        let name = Name::from_str(&self.domain)
            .map_err(|e| NetworkError::DnsResolution(format!("Invalid domain: {}", e)))?;

        let response = timeout(self.timeout, async {
            match self.record_type {
                RecordType::A => {
                    let lookup = resolver
                        .ipv4_lookup(name.clone())
                        .await
                        .map_err(|e| format!("A lookup failed: {}", e))?;
                    let ips: Vec<String> = lookup.iter().map(|ip| ip.to_string()).collect();
                    Ok(format!("A records: {}", ips.join(", ")))
                }
                RecordType::AAAA => {
                    let lookup = resolver
                        .ipv6_lookup(name.clone())
                        .await
                        .map_err(|e| format!("AAAA lookup failed: {}", e))?;
                    let ips: Vec<String> = lookup.iter().map(|ip| ip.to_string()).collect();
                    Ok(format!("AAAA records: {}", ips.join(", ")))
                }
                _ => {
                    let lookup = resolver
                        .lookup(name.clone(), self.record_type)
                        .await
                        .map_err(|e| format!("Lookup failed: {}", e))?;
                    let count = lookup.iter().count();
                    Ok(format!("{:?} records: {} found", self.record_type, count))
                }
            }
        })
        .await
        .map_err(|_| NetworkError::Timeout)?
        .map_err(|e| NetworkError::DnsResolution(e))?;

        Ok(format!("{} (via {})", response, server))
    }

    async fn check_connectivity_to_resolved_ips(&self, dns_details: &str) -> ConnectivityStatus {
        // Extract IP addresses from DNS details string
        let ips = self.extract_ips_from_dns_details(dns_details);

        if ips.is_empty() {
            return ConnectivityStatus::DnsOnlyNetworkBlocked;
        }

        let mut reachable_count = 0;
        let test_ports = [80, 443, 8080]; // Common HTTP/HTTPS ports

        for ip in ips.iter().take(2) {
            // Test first 2 IPs to avoid too many connections
            for &port in &test_ports {
                let addr = SocketAddr::new(*ip, port);

                if let Ok(_) = timeout(Duration::from_millis(1000), TcpStream::connect(addr)).await
                {
                    reachable_count += 1;
                    break; // If any port works, IP is reachable
                }
            }
        }

        if reachable_count > 0 {
            if reachable_count == ips.len().min(2) {
                ConnectivityStatus::Reachable
            } else {
                ConnectivityStatus::PartiallyReachable
            }
        } else {
            ConnectivityStatus::DnsOnlyNetworkBlocked
        }
    }

    fn extract_ips_from_dns_details(&self, dns_details: &str) -> Vec<IpAddr> {
        let mut ips = Vec::new();

        // Look for patterns like "A records: 1.2.3.4, 5.6.7.8"
        if let Some(records_part) = dns_details.split("records: ").nth(1) {
            for ip_str in records_part.split(", ") {
                if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                    ips.push(ip);
                }
            }
        }

        ips
    }
}

pub async fn test_common_dns_servers(domain: &str, record_type: RecordType) -> Vec<TestResult> {
    let servers = [
        "8.8.8.8:53",        // Google
        "8.8.4.4:53",        // Google
        "1.1.1.1:53",        // Cloudflare
        "1.0.0.1:53",        // Cloudflare
        "9.9.9.9:53",        // Quad9
        "208.67.222.222:53", // OpenDNS
        "208.67.220.220:53", // OpenDNS
    ];

    let mut results = Vec::new();

    for server_str in &servers {
        if let Ok(server) = server_str.parse::<SocketAddr>() {
            let test = DnsTest::new(domain.to_string(), record_type).with_server(server);
            results.push(test.run().await);
        }
    }

    results
}

pub async fn test_dns_over_tcp_udp(
    domain: &str,
    record_type: RecordType,
    server: SocketAddr,
) -> Vec<TestResult> {
    let mut results = Vec::new();

    // UDP test
    let udp_test = DnsTest::new(domain.to_string(), record_type)
        .with_server(server)
        .with_tcp(false);
    results.push(udp_test.run().await);

    // TCP test
    let tcp_test = DnsTest::new(domain.to_string(), record_type)
        .with_server(server)
        .with_tcp(true);
    results.push(tcp_test.run().await);

    results
}

/// Analyze DNS blocking to provide detailed explanation of what's happening
fn analyze_dns_blocking(error_msg: &str) -> String {
    let error_lower = error_msg.to_lowercase();

    if error_lower.contains("nxdomain") || error_lower.contains("name not found") {
        "DNS server returned NXDOMAIN (domain doesn't exist or is blocked at DNS level)".to_string()
    } else if error_lower.contains("servfail") || error_lower.contains("server failure") {
        "DNS server returned SERVFAIL (possibly blocked by DNS filtering service)".to_string()
    } else if error_lower.contains("refused") {
        "DNS query refused (likely blocked by DNS server policy)".to_string()
    } else if error_lower.contains("timeout") {
        "DNS query timeout (domain may be sinkholed or filtered)".to_string()
    } else if error_lower.contains("connection refused") {
        "Connection refused to DNS server (network-level blocking)".to_string()
    } else if error_lower.contains("system resolver failed") {
        "System DNS resolver blocked the query (OS or network-level filtering)".to_string()
    } else {
        format!("DNS resolution failed ({})", error_msg)
    }
}

/// Analyze IP addresses to detect DNS sinkholing
fn analyze_sinkhole_ips(ips: &[IpAddr]) -> SinkholeAnalysis {
    let mut sinkhole_ips = Vec::new();
    let mut legitimate_ips = Vec::new();

    for &ip in ips {
        if is_sinkhole_ip(ip) {
            sinkhole_ips.push(ip);
        } else {
            legitimate_ips.push(ip);
        }
    }

    if !sinkhole_ips.is_empty() && legitimate_ips.is_empty() {
        SinkholeAnalysis::FullySinkholed(sinkhole_ips)
    } else if !sinkhole_ips.is_empty() {
        SinkholeAnalysis::PartiallySinkholed {
            sinkhole_ips,
            legitimate_ips,
        }
    } else {
        SinkholeAnalysis::NotSinkholed(legitimate_ips)
    }
}

/// Check if an IP address is a known sinkhole address
fn is_sinkhole_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();

            // Common sinkhole addresses
            match octets {
                [0, 0, 0, 0] => true,         // 0.0.0.0 - most common
                [127, 0, 0, 1] => true,       // 127.0.0.1 - localhost redirect
                [127, 0, 0, 2..=255] => true, // 127.x.x.x range
                [10, 0, 0, 1] => true,        // 10.0.0.1 - router sinkhole
                [192, 168, 1, 1] => true,     // 192.168.1.1 - router sinkhole
                [192, 168, 0, 1] => true,     // 192.168.0.1 - router sinkhole
                [146, 112, 61, 104] => true,  // OpenDNS sinkhole
                [146, 112, 61, 105] => true,  // OpenDNS sinkhole
                [199, 85, 126, 10] => true,   // Norton DNS sinkhole
                [199, 85, 127, 10] => true,   // Norton DNS sinkhole
                [208, 69, 38, 170] => true,   // OpenDNS phishing block page
                [208, 69, 39, 170] => true,   // OpenDNS phishing block page
                [198, 105, 232, 6] => true,   // Quad9 sinkhole
                [198, 105, 232, 7] => true,   // Quad9 sinkhole
                [185, 228, 168, 10] => true,  // CleanBrowsing sinkhole
                [185, 228, 169, 11] => true,  // CleanBrowsing sinkhole
                _ => false,
            }
        }
        IpAddr::V6(ipv6) => {
            // IPv6 sinkhole addresses
            let segments = ipv6.segments();
            match segments {
                [0, 0, 0, 0, 0, 0, 0, 0] => true, // :: (IPv6 equivalent of 0.0.0.0)
                [0, 0, 0, 0, 0, 0, 0, 1] => true, // ::1 (IPv6 localhost)
                _ => false,
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum SinkholeAnalysis {
    NotSinkholed(Vec<IpAddr>),
    FullySinkholed(Vec<IpAddr>),
    PartiallySinkholed {
        sinkhole_ips: Vec<IpAddr>,
        legitimate_ips: Vec<IpAddr>,
    },
}

/// Debug function to show current DNS configuration
pub fn debug_dns_config() -> String {
    match system_conf::read_system_conf() {
        Ok((config, _opts)) => {
            let mut debug_info = vec!["System DNS Configuration:".to_string()];

            for name_server in config.name_servers() {
                debug_info.push(format!(
                    "  📡 DNS Server: {} ({})",
                    name_server.socket_addr,
                    match name_server.protocol {
                        Protocol::Udp => "UDP",
                        Protocol::Tcp => "TCP",
                        _ => "Other",
                    }
                ));
            }

            debug_info.push(format!("  🔍 Search domains: {:?}", config.search()));
            debug_info.join("\n")
        }
        Err(e) => format!("❌ Could not read system DNS config: {}", e),
    }
}
