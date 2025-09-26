use core::fmt::Debug;
use core::time::Duration;
use rustls::pki_types::UnixTime;
use rustls::time_provider::TimeProvider;

/// Rustls requires the user to provide a time provider.
/// This implementation provides a fixed time for testing purposes.
/// For the moment, we don't have a real time source.
#[derive(Debug, Clone)]
pub struct FixedTimeProvider {
    fixed_time: UnixTime,
}

impl FixedTimeProvider {
    /// Create a new [`FixedTimeProvider`] with a specific Unix timestamp (seconds since epoch)
    pub fn new(timestamp_secs: u64) -> Self {
        Self {
            fixed_time: UnixTime::since_unix_epoch(Duration::from_secs(timestamp_secs)),
        }
    }

    /// Create a new [`FixedTimeProvider`] with a timestamp set to December 2025
    pub fn december_2025() -> Self {
        const DECEMBER_2025: u64 = 1764979200; // Timestamp for December 6, 2025, 00:00:00 UTC
        const _SEPTEMBER_2025: u64 = 1758283200; // Timestamp for September 19, 2025, 12:00:00 UTC
        Self::new(DECEMBER_2025)
    }
}

/// Implementation of the [`TimeProvider`] trait from rustls
impl TimeProvider for FixedTimeProvider {
    /// Returns the current timestamp, in this case a fixed value
    fn current_time(&self) -> Option<UnixTime> {
        Some(self.fixed_time)
    }
}
