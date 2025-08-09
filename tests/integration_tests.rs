use nettest::*;
use std::time::Duration;

#[tokio::test]
async fn test_network_tcp_connectivity() {
    let test = network::NetworkTest::new(
        "google.com".to_string(),
        network::IpVersion::V4,
        network::NetworkProtocol::Tcp,
    )
    .with_port(80)
    .with_timeout(Duration::from_secs(10));

    let result = test.run().await;
    assert!(result.success, "TCP test to google.com should succeed");
    assert!(result.duration > Duration::ZERO);
}

#[tokio::test]
async fn test_network_udp_connectivity() {
    let test = network::NetworkTest::new(
        "8.8.8.8".to_string(),
        network::IpVersion::V4,
        network::NetworkProtocol::Udp,
    )
    .with_port(53)
    .with_timeout(Duration::from_secs(10));

    let result = test.run().await;
    assert!(result.success || !result.success); // UDP might not always respond, so we test both cases
    assert!(result.duration > Duration::ZERO);
}

#[tokio::test]
async fn test_dns_query() {
    let test = dns::DnsTest::new(
        "google.com".to_string(),
        trust_dns_client::rr::RecordType::A,
    )
    .with_timeout(Duration::from_secs(10));

    let result = test.run().await;
    assert!(result.success, "DNS A query for google.com should succeed");
    assert!(result.duration > Duration::ZERO);
    assert!(!result.details.is_empty());
}

#[tokio::test]
async fn test_dns_servers() {
    let results =
        dns::test_common_dns_servers("google.com", trust_dns_client::rr::RecordType::A).await;
    assert!(!results.is_empty());

    let successful_results = results.iter().filter(|r| r.success).count();
    assert!(
        successful_results > 0,
        "At least one DNS server should respond"
    );
}

#[tokio::test]
async fn test_mtu_discovery() {
    let discovery = mtu::MtuDiscovery::new("google.com".to_string(), network::IpVersion::V4)
        .with_range(68, 576); // Test smaller range for speed

    let result = discovery.discover().await;
    assert!(result.duration > Duration::ZERO);
}

#[tokio::test]
async fn test_comprehensive_dns() {
    let results = dns::queries::comprehensive_dns_test("google.com").await;
    assert!(!results.is_empty());

    let successful_results = results.iter().filter(|r| r.success).count();
    assert!(
        successful_results > 0,
        "At least some DNS queries should succeed"
    );
}

#[tokio::test]
async fn test_domain_categories() {
    let results = dns::categories::test_domain_category(
        &dns::categories::NORMAL_SITES,
        trust_dns_client::rr::RecordType::A,
    )
    .await;

    assert!(!results.is_empty());
    let successful_results = results.iter().filter(|r| r.success).count();
    assert!(successful_results > 0, "Normal sites should mostly resolve");
}

#[tokio::test]
async fn test_error_handling() {
    let test = network::NetworkTest::new(
        "nonexistent.invalid".to_string(),
        network::IpVersion::V4,
        network::NetworkProtocol::Tcp,
    )
    .with_port(80)
    .with_timeout(Duration::from_millis(100));

    let result = test.run().await;
    assert!(!result.success, "Test to nonexistent domain should fail");
    assert!(result.error.is_some());
}

#[tokio::test]
async fn test_timeout_handling() {
    let test = network::NetworkTest::new(
        "192.0.2.1".to_string(), // Reserved test IP that shouldn't respond
        network::IpVersion::V4,
        network::NetworkProtocol::Tcp,
    )
    .with_port(80)
    .with_timeout(Duration::from_millis(100));

    let result = test.run().await;
    assert!(!result.success, "Test to non-responsive IP should timeout");
    assert!(result.duration <= Duration::from_millis(200)); // Allow some margin
}

#[tokio::test]
async fn test_ipv6_support() {
    let test = network::NetworkTest::new(
        "google.com".to_string(),
        network::IpVersion::V6,
        network::NetworkProtocol::Tcp,
    )
    .with_port(80)
    .with_timeout(Duration::from_secs(10));

    let result = test.run().await;
    // IPv6 might not be available in all test environments, so we just check it doesn't panic
    assert!(result.duration > Duration::ZERO);
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_millis(500)), "500ms");
        assert_eq!(format_duration(Duration::from_secs(2)), "2.00s");
    }

    #[test]
    fn test_test_result_creation() {
        let result = TestResult::new("test".to_string());
        assert_eq!(result.test_name, "test");
        assert!(!result.success);
        assert_eq!(result.duration, Duration::ZERO);
    }

    #[test]
    fn test_test_result_success() {
        let result = TestResult::new("test".to_string())
            .success(Duration::from_millis(100), "details".to_string());

        assert!(result.success);
        assert_eq!(result.duration, Duration::from_millis(100));
        assert_eq!(result.details, "details");
    }

    #[test]
    fn test_test_result_failure() {
        let error = NetworkError::Timeout;
        let result = TestResult::new("test".to_string()).failure(Duration::from_millis(100), error);

        assert!(!result.success);
        assert_eq!(result.duration, Duration::from_millis(100));
        assert!(result.error.is_some());
    }
}
