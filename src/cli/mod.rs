use clap::{Parser, Subcommand, ValueEnum};
use std::net::SocketAddr;

#[derive(Parser)]
#[command(name = "nettest")]
#[command(about = "A comprehensive network connectivity and DNS testing CLI tool")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[arg(short, long, global = true, default_value = "5")]
    pub timeout: u64,

    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    #[command(about = "Test network connectivity")]
    Network {
        #[command(subcommand)]
        command: NetworkCommands,
    },
    #[command(about = "Test DNS resolution")]
    Dns {
        #[command(subcommand)]
        command: DnsCommands,
    },
    #[command(about = "Discover MTU sizes")]
    Mtu {
        #[command(subcommand)]
        command: MtuCommands,
    },
    #[command(about = "Run comprehensive tests")]
    Full {
        target: String,
        #[arg(short, long, value_enum, default_value = "both")]
        ip_version: IpVersionArg,
    },
}

#[derive(Subcommand)]
pub enum NetworkCommands {
    #[command(about = "Test TCP connectivity")]
    Tcp {
        target: String,
        #[arg(short, long, default_value = "80")]
        port: u16,
        #[arg(short, long, value_enum, default_value = "both")]
        ip_version: IpVersionArg,
    },
    #[command(about = "Test UDP connectivity")]
    Udp {
        target: String,
        #[arg(short, long, default_value = "53")]
        port: u16,
        #[arg(short, long, value_enum, default_value = "both")]
        ip_version: IpVersionArg,
    },
    #[command(about = "Test ICMP ping")]
    Ping {
        target: String,
        #[arg(short, long, default_value = "4")]
        count: u32,
        #[arg(short, long, value_enum, default_value = "both")]
        ip_version: IpVersionArg,
    },
    #[command(about = "Test common ports")]
    Ports {
        target: String,
        #[arg(short, long, value_enum, default_value = "tcp")]
        protocol: ProtocolArg,
        #[arg(short, long, value_enum, default_value = "both")]
        ip_version: IpVersionArg,
    },
}

#[derive(Subcommand)]
pub enum DnsCommands {
    #[command(about = "Query specific DNS record")]
    Query {
        domain: String,
        #[arg(short, long, value_enum, default_value = "a")]
        record_type: RecordTypeArg,
        #[arg(short, long)]
        server: Option<SocketAddr>,
        #[arg(long)]
        tcp: bool,
    },
    #[command(about = "Test DNS servers")]
    Servers {
        domain: String,
        #[arg(short, long, value_enum, default_value = "a")]
        record_type: RecordTypeArg,
    },
    #[command(about = "Test domain categories")]
    Categories {
        #[arg(short, long, value_enum)]
        category: Option<CategoryArg>,
        #[arg(short, long, value_enum, default_value = "a")]
        record_type: RecordTypeArg,
    },
    #[command(about = "Test DNS filtering effectiveness")]
    Filtering,
    #[command(about = "Show system DNS configuration")]
    Debug,
    #[command(about = "Comprehensive DNS tests")]
    Comprehensive { domain: String },
    #[command(about = "Test large DNS queries")]
    Large { domain: String },
}

#[derive(Subcommand)]
pub enum MtuCommands {
    #[command(about = "Discover MTU for target")]
    Discover {
        target: String,
        #[arg(short, long, value_enum, default_value = "both")]
        ip_version: IpVersionArg,
    },
    #[command(about = "Test common MTU sizes")]
    Common {
        target: String,
        #[arg(short, long, value_enum, default_value = "both")]
        ip_version: IpVersionArg,
    },
    #[command(about = "Test custom MTU range")]
    Range {
        target: String,
        #[arg(short, long, default_value = "68")]
        min: u16,
        #[arg(short, long, default_value = "1500")]
        max: u16,
        #[arg(short, long, value_enum, default_value = "both")]
        ip_version: IpVersionArg,
    },
}

#[derive(Clone, ValueEnum)]
pub enum IpVersionArg {
    V4,
    V6,
    Both,
}

impl IpVersionArg {
    pub fn to_versions(&self) -> Vec<crate::network::IpVersion> {
        match self {
            IpVersionArg::V4 => vec![crate::network::IpVersion::V4],
            IpVersionArg::V6 => vec![crate::network::IpVersion::V6],
            IpVersionArg::Both => {
                vec![crate::network::IpVersion::V4, crate::network::IpVersion::V6]
            }
        }
    }
}

#[derive(Clone, ValueEnum)]
pub enum ProtocolArg {
    Tcp,
    Udp,
    Both,
}

#[derive(Clone, ValueEnum)]
pub enum RecordTypeArg {
    A,
    AAAA,
    MX,
    NS,
    TXT,
    CNAME,
    SOA,
    PTR,
    All,
}

impl RecordTypeArg {
    pub fn to_record_type(&self) -> Vec<trust_dns_client::rr::RecordType> {
        match self {
            RecordTypeArg::A => vec![trust_dns_client::rr::RecordType::A],
            RecordTypeArg::AAAA => vec![trust_dns_client::rr::RecordType::AAAA],
            RecordTypeArg::MX => vec![trust_dns_client::rr::RecordType::MX],
            RecordTypeArg::NS => vec![trust_dns_client::rr::RecordType::NS],
            RecordTypeArg::TXT => vec![trust_dns_client::rr::RecordType::TXT],
            RecordTypeArg::CNAME => vec![trust_dns_client::rr::RecordType::CNAME],
            RecordTypeArg::SOA => vec![trust_dns_client::rr::RecordType::SOA],
            RecordTypeArg::PTR => vec![trust_dns_client::rr::RecordType::PTR],
            RecordTypeArg::All => vec![
                trust_dns_client::rr::RecordType::A,
                trust_dns_client::rr::RecordType::AAAA,
                trust_dns_client::rr::RecordType::MX,
                trust_dns_client::rr::RecordType::NS,
                trust_dns_client::rr::RecordType::TXT,
                trust_dns_client::rr::RecordType::CNAME,
                trust_dns_client::rr::RecordType::SOA,
            ],
        }
    }
}

#[derive(Clone, ValueEnum)]
pub enum CategoryArg {
    Normal,
    Ads,
    Spam,
    Adult,
    Malicious,
    Social,
    Streaming,
    Gaming,
    News,
    All,
}

impl CategoryArg {
    pub fn to_categories(&self) -> Vec<&'static crate::dns::categories::DomainCategory> {
        match self {
            CategoryArg::Normal => vec![&crate::dns::categories::NORMAL_SITES],
            CategoryArg::Ads => vec![&crate::dns::categories::AD_SITES],
            CategoryArg::Spam => vec![&crate::dns::categories::SPAM_SITES],
            CategoryArg::Adult => vec![&crate::dns::categories::ADULT_SITES],
            CategoryArg::Malicious => vec![&crate::dns::categories::MALICIOUS_SITES],
            CategoryArg::Social => vec![&crate::dns::categories::SOCIAL_MEDIA],
            CategoryArg::Streaming => vec![&crate::dns::categories::STREAMING_SITES],
            CategoryArg::Gaming => vec![&crate::dns::categories::GAMING_SITES],
            CategoryArg::News => vec![&crate::dns::categories::NEWS_SITES],
            CategoryArg::All => crate::dns::categories::ALL_CATEGORIES.iter().collect(),
        }
    }
}
