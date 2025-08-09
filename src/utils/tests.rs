#[cfg(test)]
mod unit_tests {
    use crate::utils::{format_duration, measure_time, NetworkError, TestResult};
    use std::time::Duration;

    #[test]
    fn test_format_duration_milliseconds() {
        let duration = Duration::from_millis(500);
        assert_eq!(format_duration(duration), "500ms");
    }

    #[test]
    fn test_format_duration_seconds() {
        let duration = Duration::from_millis(1500);
        assert_eq!(format_duration(duration), "1.50s");
    }

    #[test]
    fn test_test_result_new() {
        let result = TestResult::new("test_name".to_string());
        assert_eq!(result.test_name, "test_name");
        assert!(!result.success);
        assert_eq!(result.duration, Duration::ZERO);
        assert!(result.details.is_empty());
        assert!(result.error.is_none());
    }

    #[test]
    fn test_test_result_success() {
        let duration = Duration::from_millis(100);
        let details = "Success details".to_string();
        let result = TestResult::new("test".to_string()).success(duration, details.clone());

        assert!(result.success);
        assert_eq!(result.duration, duration);
        assert_eq!(result.details, details);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_test_result_failure() {
        let duration = Duration::from_millis(200);
        let error = NetworkError::Timeout;
        let result = TestResult::new("test".to_string()).failure(duration, error);

        assert!(!result.success);
        assert_eq!(result.duration, duration);
        assert!(result.details.is_empty());
        assert!(result.error.is_some());

        assert!(matches!(result.error, Some(NetworkError::Timeout)));
    }

    #[tokio::test]
    async fn test_measure_time() {
        let (duration, result) = measure_time(|| async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            "test_result"
        })
        .await;

        assert!(duration >= Duration::from_millis(90)); // Allow some margin
        assert!(duration <= Duration::from_millis(200)); // Upper bound
        assert_eq!(result, "test_result");
    }
}
