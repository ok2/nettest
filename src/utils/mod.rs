use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Connection timeout")]
    Timeout,
    #[error("DNS resolution failed: {0}")]
    DnsResolution(String),
    #[error("Socket creation failed: {0}")]
    SocketCreation(String),
    #[error("Network unreachable")]
    NetworkUnreachable,
    #[error("Host unreachable")]
    HostUnreachable,
    #[error("Permission denied")]
    PermissionDenied,
    #[error("Invalid MTU size: {0}")]
    InvalidMtu(u16),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Other error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, NetworkError>;

#[must_use]
pub struct TestResult {
    pub test_name: String,
    pub success: bool,
    pub duration: Duration,
    pub details: String,
    pub error: Option<NetworkError>,
}

impl TestResult {
    pub const fn new(test_name: String) -> Self {
        Self {
            test_name,
            success: false,
            duration: Duration::ZERO,
            details: String::new(),
            error: None,
        }
    }

    pub fn success(mut self, duration: Duration, details: String) -> Self {
        self.success = true;
        self.duration = duration;
        self.details = details;
        self
    }

    pub fn failure(mut self, duration: Duration, error: NetworkError) -> Self {
        self.success = false;
        self.duration = duration;
        self.error = Some(error);
        self
    }
}

pub fn format_duration(duration: Duration) -> String {
    let ms = duration.as_millis();
    if ms < 1000 {
        format!("{ms}ms")
    } else {
        format!("{:.2}s", duration.as_secs_f32())
    }
}

pub async fn measure_time<F, Fut, T>(f: F) -> (Duration, T)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let start = Instant::now();
    let result = f().await;
    let duration = start.elapsed();
    (duration, result)
}

mod tests;
