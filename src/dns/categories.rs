use super::DnsTest;
use crate::utils::TestResult;
use hickory_client::rr::RecordType;

#[derive(Clone)]
pub struct DomainCategory {
    pub name: &'static str,
    pub domains: &'static [&'static str],
    pub description: &'static str,
}

pub const NORMAL_SITES: DomainCategory = DomainCategory {
    name: "Normal Sites",
    domains: &[
        "google.com",
        "github.com",
        "stackoverflow.com",
        "wikipedia.org",
        "microsoft.com",
        "apple.com",
        "amazon.com",
        "cloudflare.com",
        "mozilla.org",
        "rust-lang.org",
    ],
    description: "Legitimate, commonly used websites",
};

pub const AD_SITES: DomainCategory = DomainCategory {
    name: "Ad Networks",
    domains: &[
        "doubleclick.net",
        "googlesyndication.com",
        "googleadservices.com",
        "facebook.com",
        "googletagmanager.com",
        "amazon-adsystem.com",
        "adsystem.amazon.com",
        "outbrain.com",
        "taboola.com",
        "criteo.com",
    ],
    description: "Advertising networks and tracking domains",
};

pub const SPAM_SITES: DomainCategory = DomainCategory {
    name: "Known Spam Domains",
    domains: &[
        // Using domains from known spam lists (these should be blocked by many DNS filters)
        "guerrillamail.com",
        "10minutemail.com",
        "tempmail.org",
        "mailinator.com",
        "spam4.me",
        "trashmail.com",
        "yopmail.com",
        "tempinbox.com",
        "throwaway.email",
        "temp-mail.org",
    ],
    description: "Temporary email services often associated with spam",
};

pub const ADULT_SITES: DomainCategory = DomainCategory {
    name: "Adult Content",
    domains: &[
        // Using well-known adult sites that are often blocked by family filters
        // These are legitimate businesses but often filtered
        "pornhub.com",
        "xvideos.com",
        "xnxx.com",
        "redtube.com",
        "youporn.com",
        "tube8.com",
        "xtube.com",
        "spankbang.com",
        "xhamster.com",
        "beeg.com",
    ],
    description: "Adult content websites often blocked by family filters",
};

pub const MALICIOUS_SITES: DomainCategory = DomainCategory {
    name: "Known Malicious Domains",
    domains: &[
        // Using domains from threat intelligence feeds (these should be blocked)
        // Note: These might not resolve or might be sinkholed
        "malware.testcategory.com",
        "phishing.testcategory.com",
        "badware.com",
        "example-malware.com",
        "test-phishing.com",
        "fake-bank-site.com",
        "malicious-download.com",
        "virus-test.com",
        "trojan-test.com",
        "ransomware-test.com",
    ],
    description: "Test domains for malicious content detection",
};

pub const SOCIAL_MEDIA: DomainCategory = DomainCategory {
    name: "Social Media",
    domains: &[
        "facebook.com",
        "twitter.com",
        "instagram.com",
        "linkedin.com",
        "youtube.com",
        "tiktok.com",
        "snapchat.com",
        "pinterest.com",
        "reddit.com",
        "discord.com",
    ],
    description: "Social media platforms",
};

pub const STREAMING_SITES: DomainCategory = DomainCategory {
    name: "Streaming Services",
    domains: &[
        "netflix.com",
        "hulu.com",
        "disney.com",
        "primevideo.com",
        "spotify.com",
        "twitch.tv",
        "youtube.com",
        "crunchyroll.com",
        "funimation.com",
        "hbomax.com",
    ],
    description: "Video and music streaming services",
};

pub const GAMING_SITES: DomainCategory = DomainCategory {
    name: "Gaming Platforms",
    domains: &[
        "steam.com",
        "epicgames.com",
        "battle.net",
        "origin.com",
        "uplay.com",
        "roblox.com",
        "minecraft.net",
        "ea.com",
        "activision.com",
        "nintendo.com",
    ],
    description: "Gaming platforms and services",
};

pub const NEWS_SITES: DomainCategory = DomainCategory {
    name: "News Websites",
    domains: &[
        "cnn.com",
        "bbc.com",
        "reuters.com",
        "nytimes.com",
        "washingtonpost.com",
        "theguardian.com",
        "npr.org",
        "ap.org",
        "bloomberg.com",
        "wsj.com",
    ],
    description: "News and media websites",
};

pub const ALL_CATEGORIES: &[DomainCategory] = &[
    NORMAL_SITES,
    AD_SITES,
    SPAM_SITES,
    ADULT_SITES,
    MALICIOUS_SITES,
    SOCIAL_MEDIA,
    STREAMING_SITES,
    GAMING_SITES,
    NEWS_SITES,
];

pub async fn test_domain_category(
    category: &DomainCategory,
    record_type: RecordType,
) -> Vec<TestResult> {
    let mut results = Vec::new();

    for &domain in category.domains {
        let test = DnsTest::new(domain.to_string(), record_type);

        // Use appropriate testing method based on category type
        let mut test_result = match category.name {
            "Known Malicious Domains" => test.run_security_test().await,
            "Ad Networks" | "Known Spam Domains" | "Adult Content" => {
                test.run_filtering_test().await
            }
            _ => test.run().await,
        };

        test_result.test_name = format!("{} - {} ({:?})", category.name, domain, record_type);
        results.push(test_result);
    }

    results
}

pub async fn test_all_categories(record_type: RecordType) -> Vec<TestResult> {
    let mut results = Vec::new();

    for category in ALL_CATEGORIES {
        let category_results = test_domain_category(category, record_type).await;
        results.extend(category_results);
    }

    results
}

pub async fn comprehensive_category_test() -> Vec<TestResult> {
    let mut results = Vec::new();

    // Test A records for all categories
    results.extend(test_all_categories(RecordType::A).await);

    // Test AAAA records for normal sites only (to avoid too many tests)
    results.extend(test_domain_category(&NORMAL_SITES, RecordType::AAAA).await);

    // Test MX records for normal sites
    results.extend(test_domain_category(&NORMAL_SITES, RecordType::MX).await);

    results
}

pub async fn test_dns_filtering_effectiveness() -> Vec<TestResult> {
    let mut results = Vec::new();

    // Test if DNS filtering is working by checking resolution of different categories
    let filter_test_categories = [
        (&AD_SITES, "Ad blocking test"),
        (&SPAM_SITES, "Spam filtering test"),
        (&ADULT_SITES, "Adult content filtering test"),
        (&MALICIOUS_SITES, "Malware filtering test"),
    ];

    for (category, test_name) in &filter_test_categories {
        let category_results = test_domain_category(category, RecordType::A).await;

        // Analyze results based on category type
        let total_domains = category_results.len();
        let (blocked_domains, resolved_domains, concerning_domains) = if category.name
            == "Known Malicious Domains"
        {
            // For malicious domains, categorize the results
            let dns_blocked = category_results
                .iter()
                .filter(|result| result.details.contains("🛡️  BLOCKED"))
                .count();
            let sinkholed = category_results
                .iter()
                .filter(|result| result.details.contains("🕳️ SINKHOLED"))
                .count();
            let total_blocked = dns_blocked + sinkholed;
            let concerning = category_results
                .iter()
                .filter(|result| {
                    result.details.contains("⚠️  RESOLVED") || result.details.contains("⚠️ MIXED")
                })
                .count();
            let other_resolved = total_domains - total_blocked - concerning;
            (total_blocked, other_resolved, concerning)
        } else if matches!(
            category.name,
            "Ad Networks" | "Known Spam Domains" | "Adult Content"
        ) {
            // For filtering categories, count based on filtering results
            let dns_filtered = category_results
                .iter()
                .filter(|result| result.details.contains("🚫 FILTERED"))
                .count();
            let sinkholed = category_results
                .iter()
                .filter(|result| result.details.contains("🕳️ SINKHOLED"))
                .count();
            let total_filtered = dns_filtered + sinkholed;
            let accessible = category_results
                .iter()
                .filter(|result| result.details.contains("📡 ACCESSIBLE"))
                .count();
            (total_filtered, accessible, 0)
        } else {
            // For other categories, traditional success/failure counting
            let blocked = category_results
                .iter()
                .filter(|result| !result.success)
                .count();
            let resolved = total_domains - blocked;
            (blocked, resolved, 0)
        };

        let summary_result = if category.name == "Known Malicious Domains" {
            let security_status = if concerning_domains > 0 {
                format!(
                    "⚠️  SECURITY CONCERN: {} potentially malicious domains resolved successfully",
                    concerning_domains
                )
            } else if blocked_domains > resolved_domains {
                format!(
                    "🛡️  GOOD SECURITY: {:.1}% of malicious domains blocked",
                    (blocked_domains as f64 / total_domains as f64) * 100.0
                )
            } else {
                format!(
                    "⚠️  WEAK FILTERING: Only {:.1}% of malicious domains blocked",
                    (blocked_domains as f64 / total_domains as f64) * 100.0
                )
            };

            TestResult::new(format!(
                "Security Analysis: {} blocked, {} resolved, {} concerning",
                blocked_domains, resolved_domains, concerning_domains
            ))
            .success(std::time::Duration::from_millis(0), security_status)
        } else {
            TestResult::new(format!(
                "{}: {} resolved, {} blocked",
                test_name, resolved_domains, blocked_domains
            ))
            .success(
                std::time::Duration::from_millis(0),
                format!(
                    "Blocking rate: {:.1}%",
                    (blocked_domains as f64 / total_domains as f64) * 100.0
                ),
            )
        };

        results.push(summary_result);
        results.extend(category_results);
    }

    results
}

/// Provide explanation of what DNS filtering results mean
pub fn explain_dns_filtering_results() -> String {
    r#"
DNS FILTERING ANALYSIS EXPLANATION:

🛡️ BLOCKED results for malicious domains = SECURITY SUCCESS
   - Domain was blocked at DNS level (good!)
   - Possible blocking levels: Router, ISP, DNS service (Cloudflare, Quad9), OS

🕳️ SINKHOLED results = ADVANCED FILTERING SUCCESS  
   - Domain redirected to harmless "sinkhole" IP addresses
   - Common sinkholes: 0.0.0.0, 127.0.0.1, router IPs
   - More sophisticated than simple blocking

⚠️ RESOLVED results for malicious domains = POTENTIAL SECURITY CONCERN  
   - Domain resolved to real IP addresses
   - Could indicate: No filtering, outdated blocklists, or domain not yet flagged

⚡ PARTIAL SINKHOLE = MIXED FILTERING
   - Some IPs sinkholed, others real (inconsistent filtering)

For other categories (Adult, Ads, etc.):
   📡 ACCESSIBLE = Normal (expected behavior without filtering)
   🚫 FILTERED = Content filtering active (family filters, ad blockers, etc.)
   🕳️ SINKHOLED = Advanced filtering (DNS redirect to safe IPs)

Common sinkhole IP addresses:
   • 0.0.0.0 - Universal "null route"
   • 127.0.0.1 - Localhost redirect
   • 192.168.1.1 - Router redirect
   • 146.112.61.104/105 - OpenDNS sinkholes
   • 198.105.232.6/7 - Quad9 sinkholes
   • 185.228.168.10 - CleanBrowsing sinkholes
"#
    .to_string()
}
