use crate::utils::{measure_time, NetworkError, Result, TestResult};
use hickory_client::op::{Message, MessageType, OpCode, Query};
use hickory_client::rr::{Name, RecordType};
use reqwest::Client;
use serde_json::Value;
use std::str::FromStr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct DohTest {
    pub domain: String,
    pub record_type: RecordType,
    pub provider: DohProvider,
    pub timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct DohProvider {
    pub name: &'static str,
    pub url: &'static str,
    pub description: &'static str,
    pub format: DohFormat,
}

#[derive(Debug, Clone)]
pub enum DohFormat {
    Json,       // Google, Cloudflare style
    WireFormat, // Quad9, AdGuard, OpenDNS style
}

// Comprehensive DoH providers list
pub const DOH_PROVIDERS: &[DohProvider] = &[
    // Google DNS - Wire format (default/standard)
    DohProvider {
        name: "Google",
        url: "https://dns.google/dns-query",
        description: "Google Public DNS (8.8.8.8)",
        format: DohFormat::WireFormat,
    },
    // Google DNS - JSON format (special variant)
    DohProvider {
        name: "Google-JSON",
        url: "https://dns.google/resolve",
        description: "Google Public DNS (8.8.8.8) - JSON variant",
        format: DohFormat::Json,
    },
    // Cloudflare DNS - Wire format variants (default/standard)
    DohProvider {
        name: "Cloudflare",
        url: "https://1.1.1.1/dns-query",
        description: "Cloudflare DNS Primary (1.1.1.1)",
        format: DohFormat::WireFormat,
    },
    DohProvider {
        name: "Cloudflare-Family",
        url: "https://1.1.1.2/dns-query",
        description: "Cloudflare for Families (1.1.1.2) - Blocks malware/adult",
        format: DohFormat::WireFormat,
    },
    DohProvider {
        name: "Cloudflare-Security",
        url: "https://1.1.1.3/dns-query",
        description: "Cloudflare for Families (1.1.1.3) - Blocks malware only",
        format: DohFormat::WireFormat,
    },
    // Cloudflare DNS - JSON format variants (special variants)
    DohProvider {
        name: "Cloudflare-JSON",
        url: "https://1.1.1.1/dns-query",
        description: "Cloudflare DNS Primary (1.1.1.1) - JSON variant",
        format: DohFormat::Json,
    },
    DohProvider {
        name: "Cloudflare-Family-JSON",
        url: "https://1.1.1.2/dns-query",
        description: "Cloudflare for Families (1.1.1.2) - Blocks malware/adult - JSON variant",
        format: DohFormat::Json,
    },
    DohProvider {
        name: "Cloudflare-Security-JSON",
        url: "https://1.1.1.3/dns-query",
        description: "Cloudflare for Families (1.1.1.3) - Blocks malware only - JSON variant",
        format: DohFormat::Json,
    },
    // Quad9 DNS - All variants
    DohProvider {
        name: "Quad9",
        url: "https://dns.quad9.net/dns-query",
        description: "Quad9 Secure (9.9.9.9) - Blocks malicious domains",
        format: DohFormat::WireFormat,
    },
    DohProvider {
        name: "Quad9-Unsecured",
        url: "https://dns10.quad9.net/dns-query",
        description: "Quad9 Unsecured (9.9.9.10) - No domain blocking",
        format: DohFormat::WireFormat,
    },
    DohProvider {
        name: "Quad9-ECS",
        url: "https://dns11.quad9.net/dns-query",
        description: "Quad9 ECS (9.9.9.11) - Blocks malicious + EDNS Client Subnet",
        format: DohFormat::WireFormat,
    },
    // OpenDNS
    DohProvider {
        name: "OpenDNS",
        url: "https://doh.opendns.com/dns-query",
        description: "OpenDNS Standard (208.67.222.222)",
        format: DohFormat::WireFormat,
    },
    DohProvider {
        name: "OpenDNS-Family",
        url: "https://doh.familyshield.opendns.com/dns-query",
        description: "OpenDNS FamilyShield (208.67.222.123) - Blocks adult content",
        format: DohFormat::WireFormat,
    },
    // AdGuard DNS - All variants
    DohProvider {
        name: "AdGuard",
        url: "https://dns.adguard.com/dns-query",
        description: "AdGuard DNS (94.140.14.14) - Blocks ads and trackers",
        format: DohFormat::WireFormat,
    },
    DohProvider {
        name: "AdGuard-Family",
        url: "https://dns-family.adguard.com/dns-query",
        description: "AdGuard DNS Family (94.140.14.15) - Blocks ads, trackers, and adult content",
        format: DohFormat::WireFormat,
    },
    DohProvider {
        name: "AdGuard-Unfiltered",
        url: "https://dns-unfiltered.adguard.com/dns-query",
        description: "AdGuard DNS Unfiltered (94.140.14.140) - No filtering",
        format: DohFormat::WireFormat,
    },
];

impl DohTest {
    pub fn new(domain: String, record_type: RecordType, provider: DohProvider) -> Self {
        Self {
            domain,
            record_type,
            provider,
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub async fn run(&self) -> TestResult {
        let test_name = format!(
            "DoH {:?} query for {} via {}",
            self.record_type, self.domain, self.provider.name
        );

        let (duration, result) = measure_time(|| async { self.query_doh().await }).await;

        match result {
            Ok(response) => TestResult::new(test_name).success(duration, response),
            Err(error) => TestResult::new(test_name).failure(duration, error),
        }
    }

    async fn query_doh(&self) -> Result<String> {
        let client = Client::builder()
            .timeout(self.timeout)
            .user_agent("NetTest/1.0")
            .build()
            .map_err(|e| NetworkError::Other(format!("Failed to create HTTP client: {}", e)))?;

        match self.provider.format {
            DohFormat::Json => self.query_doh_json(&client).await,
            DohFormat::WireFormat => self.query_doh_wire_format(&client).await,
        }
    }

    async fn query_doh_json(&self, client: &Client) -> Result<String> {
        // Build URL with standard DoH parameters (Google/Cloudflare style)
        let url = format!(
            "{}?name={}&type={}",
            self.provider.url,
            self.domain,
            self.record_type_to_number()
        );

        let response = client
            .get(&url)
            .header("Accept", "application/dns-json")
            .send()
            .await
            .map_err(|e| NetworkError::Other(format!("DoH request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(NetworkError::Other(format!(
                "DoH server returned status: {}",
                response.status()
            )));
        }

        let json_response: Value = response
            .json()
            .await
            .map_err(|e| NetworkError::Other(format!("Failed to parse DoH response: {}", e)))?;

        self.parse_doh_response(&json_response)
    }

    async fn query_doh_wire_format(&self, client: &Client) -> Result<String> {
        // Create DNS query packet
        let dns_packet = self.create_dns_query_packet()?;

        let response = client
            .post(self.provider.url)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(dns_packet)
            .send()
            .await
            .map_err(|e| NetworkError::Other(format!("DoH request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(NetworkError::Other(format!(
                "DoH server returned status: {}",
                response.status()
            )));
        }

        let response_bytes = response
            .bytes()
            .await
            .map_err(|e| NetworkError::Other(format!("Failed to read DoH response: {}", e)))?;

        self.parse_dns_response_packet(&response_bytes)
    }

    fn create_dns_query_packet(&self) -> Result<Vec<u8>> {
        // Create a DNS query message
        let name = Name::from_str(&self.domain)
            .map_err(|e| NetworkError::Other(format!("Invalid domain name: {}", e)))?;

        let query = Query::query(name, self.record_type);
        let mut message = Message::new();
        message
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(true)
            .add_query(query);

        // Serialize to bytes
        message
            .to_vec()
            .map_err(|e| NetworkError::Other(format!("Failed to serialize DNS query: {}", e)))
    }

    fn parse_dns_response_packet(&self, response_bytes: &[u8]) -> Result<String> {
        // Parse the DNS response packet
        let message = Message::from_vec(response_bytes).map_err(|e| {
            NetworkError::Other(format!("Failed to parse DNS response packet: {}", e))
        })?;

        // Check response code
        if message.response_code() != hickory_client::op::ResponseCode::NoError {
            return Err(NetworkError::DnsResolution(format!(
                "DNS query failed with response code: {:?}",
                message.response_code()
            )));
        }

        let answers = message.answers();
        if answers.is_empty() {
            return Ok(format!("{:?} records: (none found)", self.record_type));
        }

        let mut records = Vec::new();
        for answer in answers {
            if answer.record_type() == self.record_type {
                match answer.data() {
                    Some(rdata) => records.push(rdata.to_string()),
                    None => continue,
                }
            }
        }

        if records.is_empty() {
            Ok(format!("{:?} records: (none found)", self.record_type))
        } else {
            Ok(format!(
                "{:?} records: {}",
                self.record_type,
                records.join(", ")
            ))
        }
    }

    fn record_type_to_number(&self) -> u16 {
        match self.record_type {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::PTR => 12,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::AAAA => 28,
            _ => 1, // Default to A record
        }
    }

    fn parse_doh_response(&self, response: &Value) -> Result<String> {
        let status = response["Status"]
            .as_u64()
            .ok_or_else(|| NetworkError::Other("Invalid DoH response format".to_string()))?;

        if status != 0 {
            let status_text = match status {
                1 => "Format Error",
                2 => "Server Failure",
                3 => "Name Error (NXDOMAIN)",
                4 => "Not Implemented",
                5 => "Refused",
                _ => "Unknown Error",
            };
            return Err(NetworkError::DnsResolution(format!(
                "DoH query failed with status {}: {}",
                status, status_text
            )));
        }

        let empty_vec = Vec::new();
        let answers = response["Answer"].as_array().unwrap_or(&empty_vec);

        if answers.is_empty() {
            return Ok(format!("{:?} records: (none found)", self.record_type));
        }

        let mut records = Vec::new();
        for answer in answers {
            if let Some(data) = answer["data"].as_str() {
                records.push(data.to_string());
            }
        }

        if records.is_empty() {
            Ok(format!("{:?} records: (none found)", self.record_type))
        } else {
            Ok(format!(
                "{:?} records: {}",
                self.record_type,
                records.join(", ")
            ))
        }
    }
}

pub async fn test_doh_providers(domain: &str, record_type: RecordType) -> Vec<TestResult> {
    let mut results = Vec::new();

    for provider in DOH_PROVIDERS {
        let test = DohTest::new(domain.to_string(), record_type, provider.clone());
        results.push(test.run().await);
    }

    results
}

pub async fn test_doh_comprehensive(domain: &str) -> Vec<TestResult> {
    let mut results = Vec::new();

    // Test A records with JSON-compatible providers (Google and Cloudflare variants)
    let json_compatible_providers = [
        &DOH_PROVIDERS[0], // Google
        &DOH_PROVIDERS[1], // Cloudflare Primary
        &DOH_PROVIDERS[2], // Cloudflare-Family
        &DOH_PROVIDERS[3], // Cloudflare-Security
    ];

    for provider in json_compatible_providers {
        let test = DohTest::new(domain.to_string(), RecordType::A, provider.clone());
        results.push(test.run().await);
    }

    // Test AAAA records with the same JSON-compatible providers
    for provider in json_compatible_providers {
        let test = DohTest::new(domain.to_string(), RecordType::AAAA, provider.clone());
        results.push(test.run().await);
    }

    results
}

pub fn get_provider_by_name(name: &str) -> Option<&'static DohProvider> {
    DOH_PROVIDERS
        .iter()
        .find(|provider| provider.name.to_lowercase() == name.to_lowercase())
}

pub fn list_doh_providers() -> Vec<TestResult> {
    let mut results = Vec::new();

    for provider in DOH_PROVIDERS {
        let details = format!("{} - {}", provider.url, provider.description);
        let result = TestResult::new(format!("DoH Provider: {}", provider.name))
            .success(Duration::from_millis(0), details);
        results.push(result);
    }

    results
}
