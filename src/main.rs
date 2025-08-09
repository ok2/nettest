use clap::Parser;
use colored::*;
use env_logger;
use indicatif::{ProgressBar, ProgressStyle};
use nettest::*;
use serde_json;
use std::time::Duration;

#[tokio::main]
async fn main() {
    let cli = cli::Cli::parse();

    env_logger::Builder::from_default_env()
        .filter_level(if cli.verbose {
            log::LevelFilter::Info
        } else {
            log::LevelFilter::Warn
        })
        .init();

    let timeout = Duration::from_secs(cli.timeout);

    let results = match cli.command {
        cli::Commands::Network { command } => handle_network_command(command, timeout).await,
        cli::Commands::Dns { command } => handle_dns_command(command, timeout).await,
        cli::Commands::Mtu { command } => handle_mtu_command(command, timeout).await,
        cli::Commands::Full { target, ip_version } => {
            handle_full_test(target, ip_version, timeout).await
        }
    };

    if cli.json {
        print_results_json(&results);
    } else {
        print_results_human(&results);
    }

    let failed_tests = results.iter().filter(|r| !r.success).count();
    if failed_tests > 0 {
        std::process::exit(1);
    }
}

async fn handle_network_command(
    command: cli::NetworkCommands,
    timeout: Duration,
) -> Vec<TestResult> {
    match command {
        cli::NetworkCommands::Tcp {
            target,
            port,
            ip_version,
        } => {
            let mut results = Vec::new();
            for version in ip_version.to_versions() {
                let test = network::NetworkTest::new(
                    target.clone(),
                    version,
                    network::NetworkProtocol::Tcp,
                )
                .with_port(port)
                .with_timeout(timeout);
                results.push(test.run().await);
            }
            results
        }
        cli::NetworkCommands::Udp {
            target,
            port,
            ip_version,
        } => {
            let mut results = Vec::new();
            for version in ip_version.to_versions() {
                let test = network::NetworkTest::new(
                    target.clone(),
                    version,
                    network::NetworkProtocol::Udp,
                )
                .with_port(port)
                .with_timeout(timeout);
                results.push(test.run().await);
            }
            results
        }
        cli::NetworkCommands::Ping {
            target,
            count,
            ip_version,
        } => {
            let mut results = Vec::new();
            for version in ip_version.to_versions() {
                let ping_results = network::ping_test(&target, version, count).await;
                results.extend(ping_results);
            }
            results
        }
        cli::NetworkCommands::Ports {
            target,
            protocol,
            ip_version,
        } => {
            let mut results = Vec::new();
            for version in ip_version.to_versions() {
                match protocol {
                    cli::ProtocolArg::Tcp => {
                        let tcp_results = network::test_tcp_common_ports(&target, version).await;
                        results.extend(tcp_results);
                    }
                    cli::ProtocolArg::Udp => {
                        let udp_results = network::test_udp_common_ports(&target, version).await;
                        results.extend(udp_results);
                    }
                    cli::ProtocolArg::Both => {
                        let tcp_results = network::test_tcp_common_ports(&target, version).await;
                        let udp_results = network::test_udp_common_ports(&target, version).await;
                        results.extend(tcp_results);
                        results.extend(udp_results);
                    }
                }
            }
            results
        }
    }
}

async fn handle_dns_command(command: cli::DnsCommands, timeout: Duration) -> Vec<TestResult> {
    match command {
        cli::DnsCommands::Query {
            domain,
            record_type,
            server,
            tcp,
        } => {
            let mut results = Vec::new();
            for rt in record_type.to_record_type() {
                let mut test = dns::DnsTest::new(domain.clone(), rt)
                    .with_timeout(timeout)
                    .with_tcp(tcp);

                if let Some(server_addr) = server {
                    test = test.with_server(server_addr);
                }

                results.push(test.run().await);
            }
            results
        }
        cli::DnsCommands::Servers {
            domain,
            record_type,
        } => {
            let mut results = Vec::new();
            for rt in record_type.to_record_type() {
                let server_results = dns::test_common_dns_servers(&domain, rt).await;
                results.extend(server_results);
            }
            results
        }
        cli::DnsCommands::Categories {
            category,
            record_type,
        } => {
            let mut results = Vec::new();
            let categories = category
                .map(|c| c.to_categories())
                .unwrap_or_else(|| dns::categories::ALL_CATEGORIES.iter().collect());

            for rt in record_type.to_record_type() {
                for cat in &categories {
                    let cat_results = dns::categories::test_domain_category(cat, rt).await;
                    results.extend(cat_results);
                }
            }
            results
        }
        cli::DnsCommands::Filtering => dns::categories::test_dns_filtering_effectiveness().await,
        cli::DnsCommands::Debug => {
            // Create a debug result showing DNS configuration
            let debug_info = dns::debug_dns_config();
            vec![TestResult::new("DNS Configuration Debug".to_string())
                .success(Duration::from_millis(0), debug_info)]
        }
        cli::DnsCommands::Comprehensive { domain } => {
            dns::queries::comprehensive_dns_test(&domain).await
        }
        cli::DnsCommands::Large { domain } => dns::queries::test_large_dns_queries(&domain).await,
    }
}

async fn handle_mtu_command(command: cli::MtuCommands, _timeout: Duration) -> Vec<TestResult> {
    match command {
        cli::MtuCommands::Discover { target, ip_version } => {
            let mut results = Vec::new();
            for version in ip_version.to_versions() {
                let result = mtu::full_mtu_discovery(&target, version).await;
                results.push(result);
            }
            results
        }
        cli::MtuCommands::Common { target, ip_version } => {
            let mut results = Vec::new();
            for version in ip_version.to_versions() {
                let common_results = mtu::test_common_mtu_sizes(&target, version).await;
                results.extend(common_results);
            }
            results
        }
        cli::MtuCommands::Range {
            target,
            min,
            max,
            ip_version,
        } => {
            let mut results = Vec::new();
            for version in ip_version.to_versions() {
                let discovery =
                    mtu::MtuDiscovery::new(target.clone(), version).with_range(min, max);
                results.push(discovery.discover().await);
            }
            results
        }
    }
}

async fn handle_full_test(
    target: String,
    ip_version: cli::IpVersionArg,
    timeout: Duration,
) -> Vec<TestResult> {
    let versions = ip_version.to_versions();
    let total_tests = versions.len() * 10; // Rough estimate

    let pb = ProgressBar::new(total_tests as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} {msg}",
            )
            .unwrap()
            .progress_chars("█▉▊▋▌▍▎▏  "),
    );

    let mut all_results = Vec::new();

    for version in versions {
        pb.set_message(format!("Testing {:?} connectivity...", version));

        // Network tests
        let tcp_test =
            network::NetworkTest::new(target.clone(), version, network::NetworkProtocol::Tcp)
                .with_port(80)
                .with_timeout(timeout);
        all_results.push(tcp_test.run().await);
        pb.inc(1);

        let udp_test =
            network::NetworkTest::new(target.clone(), version, network::NetworkProtocol::Udp)
                .with_port(53)
                .with_timeout(timeout);
        all_results.push(udp_test.run().await);
        pb.inc(1);

        // ICMP test
        let ping_results = network::ping_test(&target, version, 3).await;
        all_results.extend(ping_results);
        pb.inc(3);

        // MTU discovery
        pb.set_message(format!("Discovering MTU for {:?}...", version));
        let mtu_result = mtu::full_mtu_discovery(&target, version).await;
        all_results.push(mtu_result);
        pb.inc(1);

        // Common MTU sizes
        let mtu_common = mtu::test_common_mtu_sizes(&target, version).await;
        all_results.extend(mtu_common);
        pb.inc(1);
    }

    // DNS tests
    pb.set_message("Testing DNS resolution...");
    let dns_results = dns::queries::comprehensive_dns_test(&target).await;
    all_results.extend(dns_results);
    pb.inc(1);

    // DNS servers test
    let dns_servers =
        dns::test_common_dns_servers(&target, trust_dns_client::rr::RecordType::A).await;
    all_results.extend(dns_servers);
    pb.inc(1);

    pb.finish_with_message("Testing complete!");
    all_results
}

fn print_results_human(results: &[TestResult]) {
    println!("\n{}", "=".repeat(80).blue());
    println!("{}", "Network Test Results".bold().blue());
    println!("{}", "=".repeat(80).blue());

    let mut success_count = 0;
    let mut failure_count = 0;

    for result in results {
        let status = if result.success {
            success_count += 1;
            "PASS".green().bold()
        } else {
            failure_count += 1;
            "FAIL".red().bold()
        };

        let duration_str = utils::format_duration(result.duration);

        println!("{} {} ({})", status, result.test_name, duration_str.cyan());

        if result.success {
            if !result.details.is_empty() {
                println!("  ✓ {}", result.details.green());
            }
        } else {
            if let Some(ref error) = result.error {
                println!("  ✗ {}", error.to_string().red());
            }
        }
        println!();
    }

    println!("{}", "-".repeat(80).blue());
    println!(
        "Summary: {} passed, {} failed, {} total",
        success_count.to_string().green().bold(),
        failure_count.to_string().red().bold(),
        results.len().to_string().blue().bold()
    );

    if failure_count > 0 {
        println!("{}", "Some tests failed!".red().bold());
    } else {
        println!("{}", "All tests passed!".green().bold());
    }
}

fn print_results_json(results: &[TestResult]) {
    #[derive(serde::Serialize)]
    struct JsonResult {
        test_name: String,
        success: bool,
        duration_ms: u128,
        details: Option<String>,
        error: Option<String>,
    }

    let json_results: Vec<JsonResult> = results
        .iter()
        .map(|r| JsonResult {
            test_name: r.test_name.clone(),
            success: r.success,
            duration_ms: r.duration.as_millis(),
            details: if r.success && !r.details.is_empty() {
                Some(r.details.clone())
            } else {
                None
            },
            error: r.error.as_ref().map(|e| e.to_string()),
        })
        .collect();

    println!("{}", serde_json::to_string_pretty(&json_results).unwrap());
}
