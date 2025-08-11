//! Integration test examples demonstrating `NetTest` library usage.
//!
//! These tests serve as comprehensive examples of how to use the `NetTest` library
//! for various network testing scenarios. They can be run with `cargo test --test integration_examples`.

use hickory_client::rr::RecordType;
use nettest::*;
use std::time::Duration;
use tokio;

#[tokio::test]
async fn example_basic_dns_query() {
    // Example: Basic DNS A record query
    let test = dns::DnsTest::new("google.com".to_string(), RecordType::A);
    let result = test.run().await;

    // DNS queries should generally succeed for major domains
    assert!(
        result.success,
        "DNS query should succeed for google.com: {:?}",
        result.error
    );
    assert!(result.details.contains("A records"));
    assert!(result.duration < Duration::from_secs(10));
}

#[tokio::test]
async fn example_dns_with_custom_server() {
    // Example: Query specific DNS server with timeout
    use std::net::SocketAddr;
    use std::str::FromStr;

    let server = SocketAddr::from_str("8.8.8.8:53").unwrap();
    let test = dns::DnsTest::new("cloudflare.com".to_string(), RecordType::A)
        .with_server(server)
        .with_timeout(Duration::from_secs(5))
        .with_tcp(false);

    let result = test.run().await;

    assert!(
        result.success,
        "Custom DNS server query failed: {:?}",
        result.error
    );
    assert!(result.test_name.contains("8.8.8.8"));
    assert!(result.details.contains("via 8.8.8.8"));
}

#[tokio::test]
async fn example_comprehensive_dns_testing() {
    // Example: Test against all DNS providers
    let results = dns::test_common_dns_servers("example.com", RecordType::A).await;

    // Should test at least 30 providers (23 traditional + 16 DoH)
    assert!(
        results.len() >= 30,
        "Should test many DNS providers, got {}",
        results.len()
    );

    // Count successful vs failed
    let successful = results.iter().filter(|r| r.success).count();
    let total = results.len();

    println!(
        "DNS provider test results: {}/{} successful",
        successful, total
    );

    // At least 50% of providers should work for a major domain
    assert!(
        successful * 2 >= total,
        "At least 50% of DNS providers should work"
    );

    // Should have both traditional and DoH tests
    let has_traditional = results.iter().any(|r| r.test_name.contains("8.8.8.8"));
    let has_doh = results.iter().any(|r| r.test_name.contains("DoH"));

    assert!(has_traditional, "Should include traditional DNS tests");
    assert!(has_doh, "Should include DoH tests");
}

#[tokio::test]
async fn example_doh_testing() {
    // Example: DNS-over-HTTPS testing with multiple providers
    let results = dns::doh::test_doh_providers("google.com", RecordType::A).await;

    assert!(!results.is_empty(), "Should have DoH provider results");

    let successful = results.iter().filter(|r| r.success).count();
    println!(
        "DoH provider test results: {}/{} successful",
        successful,
        results.len()
    );

    // Should have results from multiple providers
    let provider_names: std::collections::HashSet<_> = results
        .iter()
        .map(|r| {
            // Extract provider name from test name
            if let Some(pos) = r.test_name.find(" via ") {
                &r.test_name[pos + 5..]
            } else {
                "unknown"
            }
        })
        .collect();

    assert!(
        provider_names.len() >= 10,
        "Should test multiple DoH providers"
    );
}

#[tokio::test]
async fn example_network_connectivity() {
    // Example: Basic network connectivity testing
    let tcp_test = network::NetworkTest::new(
        "google.com".to_string(),
        network::IpVersion::V4,
        network::NetworkProtocol::Tcp,
    )
    .with_port(80);

    let result = tcp_test.run().await;

    assert!(
        result.success,
        "TCP connection to google.com:80 should succeed: {:?}",
        result.error
    );
    assert!(result.test_name.contains("Tcp test to"));
    assert!(result.test_name.contains("google.com"));
    assert!(result.test_name.contains(":80"));
}

#[tokio::test]
async fn example_ping_testing() {
    // Example: Multiple ping tests
    let results = network::ping_test("8.8.8.8", network::IpVersion::V4, 3).await;

    assert_eq!(results.len(), 3, "Should perform 3 ping tests");

    for (i, result) in results.iter().enumerate() {
        let expected_name = format!("ICMP ping #{} to 8.8.8.8 (V4)", i + 1);
        assert_eq!(result.test_name, expected_name);

        // Ping to 8.8.8.8 should generally work
        if !result.success {
            println!("Warning: Ping #{} failed: {:?}", i + 1, result.error);
        }
    }
}

#[tokio::test]
async fn example_mtu_discovery() {
    // Example: MTU discovery with custom range
    let discovery = mtu::MtuDiscovery::new("cloudflare.com".to_string(), network::IpVersion::V4)
        .with_range(1200, 1600);

    let result = discovery.discover().await;

    // MTU discovery might fail due to network restrictions, but the structure should be correct
    assert!(result.test_name.contains("MTU discovery"));
    assert!(result.test_name.contains("cloudflare.com"));

    if result.success {
        assert!(result.details.contains("Discovered MTU"));
        println!("MTU discovery result: {}", result.details);
    } else {
        println!(
            "MTU discovery failed (expected in some environments): {:?}",
            result.error
        );
    }
}

#[tokio::test]
async fn example_common_mtu_testing() {
    // Example: Test common MTU sizes
    let results = mtu::test_common_mtu_sizes("google.com", network::IpVersion::V4, false).await;

    assert!(!results.is_empty(), "Should test multiple MTU sizes");

    for result in &results {
        assert!(result.test_name.contains("MTU test"));
        assert!(result.test_name.contains("google.com"));
    }

    let successful = results.iter().filter(|r| r.success).count();
    println!(
        "MTU size tests: {}/{} successful",
        successful,
        results.len()
    );
}

#[tokio::test]
async fn example_txt_record_handling() {
    // Example: Large TXT record handling (tests EDNS0 support)
    let test = dns::DnsTest::new("google.com".to_string(), RecordType::TXT);
    let result = test.run().await;

    // Google has large TXT records, this tests EDNS0 support
    if result.success {
        assert!(result.details.contains("TXT records"));
        println!("TXT record result: {}", result.details);

        // Should complete reasonably quickly with EDNS0
        assert!(result.duration < Duration::from_secs(5));
    } else {
        println!("TXT query failed: {:?}", result.error);
    }
}

#[tokio::test]
async fn example_security_testing() {
    // Example: Security-focused DNS testing
    let test = dns::DnsTest::new("example.com".to_string(), RecordType::A);

    // Test security analysis
    let security_result = test.run_security_test().await;
    assert!(security_result.test_name.contains("DNS"));

    // Security tests interpret results differently than normal tests
    println!("Security test result: {}", security_result.test_name);
}

#[tokio::test]
async fn example_dns_filtering_analysis() {
    // Example: Test DNS filtering capabilities
    let results = dns::categories::test_dns_filtering_effectiveness().await;

    assert!(!results.is_empty(), "Should have filtering test results");

    for result in &results {
        println!(
            "Filtering test: {} - Success: {}",
            result.test_name, result.success
        );
    }
}

#[tokio::test]
async fn example_comprehensive_dns_queries() {
    // Example: Test multiple record types
    let record_types = [
        RecordType::A,
        RecordType::AAAA,
        RecordType::MX,
        RecordType::NS,
        RecordType::TXT,
    ];

    for record_type in &record_types {
        let test = dns::DnsTest::new("google.com".to_string(), *record_type);
        let result = test.run().await;

        println!(
            "Record type {:?}: Success = {}",
            record_type, result.success
        );

        if result.success {
            assert!(result
                .details
                .contains(&format!("{:?} records", record_type)));
        }
    }
}

#[tokio::test]
async fn example_ipv6_support() {
    // Example: IPv6 connectivity testing
    let test = network::NetworkTest::new(
        "google.com".to_string(),
        network::IpVersion::V6,
        network::NetworkProtocol::Tcp,
    )
    .with_port(80);

    let result = test.run().await;

    // IPv6 may not be available in all environments
    if result.success {
        assert!(result.test_name.contains("V6"));
        println!("IPv6 test successful: {}", result.details);
    } else {
        println!("IPv6 test failed (may be expected): {:?}", result.error);
    }
}

#[tokio::test]
async fn example_timeout_handling() {
    // Example: Testing timeout behavior
    let test = dns::DnsTest::new(
        "nonexistent-domain-12345.invalid".to_string(),
        RecordType::A,
    )
    .with_timeout(Duration::from_millis(100)); // Very short timeout

    let result = test.run().await;

    // Should either fail due to nonexistent domain or timeout
    assert!(!result.success);
    assert!(result.duration <= Duration::from_secs(1));

    if let Some(error) = result.error {
        match error {
            NetworkError::Timeout => println!("Request timed out as expected"),
            NetworkError::DnsResolution(_) => println!("DNS resolution failed as expected"),
            _ => println!("Other error: {:?}", error),
        }
    }
}

#[tokio::test]
async fn example_concurrent_testing() {
    // Example: Concurrent testing capabilities
    use tokio::time::Instant;

    let start = Instant::now();

    // Run multiple tests concurrently
    let futures = vec![
        tokio::spawn(async {
            let test = dns::DnsTest::new("google.com".to_string(), RecordType::A);
            test.run().await
        }),
        tokio::spawn(async {
            let test = dns::DnsTest::new("cloudflare.com".to_string(), RecordType::A);
            test.run().await
        }),
        tokio::spawn(async {
            let test = dns::DnsTest::new("github.com".to_string(), RecordType::A);
            test.run().await
        }),
    ];

    let results = futures::future::join_all(futures).await;
    let duration = start.elapsed();

    // Concurrent execution should be faster than sequential
    assert!(duration < Duration::from_secs(10));

    for result in results {
        let test_result = result.unwrap();
        println!(
            "Concurrent test: {} - Success: {}",
            test_result.test_name, test_result.success
        );
    }
}
