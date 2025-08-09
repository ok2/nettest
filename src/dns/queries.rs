use super::DnsTest;
use crate::utils::TestResult;
use trust_dns_client::rr::RecordType;

pub async fn comprehensive_dns_test(domain: &str) -> Vec<TestResult> {
    let mut results = Vec::new();

    let record_types = [
        RecordType::A,
        RecordType::AAAA,
        RecordType::MX,
        RecordType::NS,
        RecordType::TXT,
        RecordType::CNAME,
        RecordType::SOA,
    ];

    for record_type in &record_types {
        let test = DnsTest::new(domain.to_string(), *record_type);
        results.push(test.run().await);
    }

    results
}

pub async fn test_large_dns_queries(domain: &str) -> Vec<TestResult> {
    let mut results = Vec::new();

    // Test with a domain that has large TXT records
    let large_txt_domains = [
        "_dmarc.google.com",
        "google.com", // Often has large TXT records for verification
        "_domainkey.google.com",
    ];

    for test_domain in &large_txt_domains {
        let test = DnsTest::new(test_domain.to_string(), RecordType::TXT);
        results.push(test.run().await);
    }

    // Test DNSSEC-related records if available
    let dnssec_types = [
        RecordType::DS,
        RecordType::RRSIG,
        RecordType::DNSKEY,
        RecordType::NSEC,
        RecordType::NSEC3,
    ];

    for record_type in &dnssec_types {
        let test = DnsTest::new(domain.to_string(), *record_type);
        results.push(test.run().await);
    }

    results
}

pub async fn test_dns_amplification_domains() -> Vec<TestResult> {
    // Test domains that might be used in DNS amplification attacks
    // These are legitimate tests to check if the resolver handles them properly
    let test_domains = [
        "isc.org",       // Often has large responses
        "ripe.net",      // Registry with comprehensive records
        "version.bind",  // Special query
        "hostname.bind", // Special query
    ];

    let mut results = Vec::new();

    for domain in &test_domains {
        let test = DnsTest::new(domain.to_string(), RecordType::TXT);
        results.push(test.run().await);
    }

    results
}

pub async fn test_reverse_dns_lookups() -> Vec<TestResult> {
    let mut results = Vec::new();

    let test_ips = [
        "8.8.8.8",        // Google DNS
        "1.1.1.1",        // Cloudflare DNS
        "208.67.222.222", // OpenDNS
    ];

    for ip in &test_ips {
        // Convert IP to reverse DNS format
        let reverse_domain = if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
            let octets = addr.octets();
            format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            )
        } else {
            continue;
        };

        let test = DnsTest::new(reverse_domain, RecordType::PTR);
        results.push(test.run().await);
    }

    results
}

pub async fn test_international_domains() -> Vec<TestResult> {
    let mut results = Vec::new();

    // Test internationalized domain names
    let international_domains = [
        "xn--n3h.com",           // ☃.com (snowman emoji)
        "xn--e1afmkfd.xn--p1ai", // пример.рф (example.rf in Russian)
        "xn--fsq.xn--0zwm56d",   // 测试.测试 (test.test in Chinese)
    ];

    for domain in &international_domains {
        let test = DnsTest::new(domain.to_string(), RecordType::A);
        results.push(test.run().await);
    }

    results
}

pub async fn test_dns_query_sizes() -> Vec<TestResult> {
    let mut results = Vec::new();

    // Test queries that might produce different response sizes
    let size_test_domains = [
        ("short.example", "Short domain name"),
        (
            "very-long-subdomain-name-that-tests-dns-limits.example.com",
            "Long domain name",
        ),
        (
            "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.example.com",
            "Deep subdomain",
        ),
    ];

    for (domain, description) in &size_test_domains {
        let mut test_result = DnsTest::new(domain.to_string(), RecordType::A).run().await;
        test_result.test_name = format!("DNS query size test: {}", description);
        results.push(test_result);
    }

    results
}
