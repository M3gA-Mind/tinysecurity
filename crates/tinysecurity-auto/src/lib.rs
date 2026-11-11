//! Optional native Jev scoring with local thresholds, bounded budgets and caches.
//!
//! Only the durable approval engine consumes scores, after verified policy gates.
//! Scores never form a reusable permission or authenticated human authority.
//!
//! ```
//! use tinysecurity_auto::Clock;
//! #[derive(Debug)]
//! struct Fixed;
//! impl Clock for Fixed { fn milliseconds(&self) -> u64 { 0 } }
//! assert_eq!(Fixed.milliseconds(), 0);
//! ```
mod budget;
mod cache;
mod error;
mod host;
mod judge;
pub mod rules;
pub use error::{Error, Result};
pub use host::{CredentialSource, HOST_CREDENTIAL_TTL_MS};
pub use judge::{Engine, Input, JudgeClient, SdkClient};
/// Injected monotonic time for shared budgets and exact-score cache expiration.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Milliseconds from a stable origin; any rollback disables scoring.
    fn milliseconds(&self) -> u64;
}
/// Monotonic system clock with no wall-clock resets.
#[derive(Debug)]
pub struct SystemClock(std::time::Instant);
impl Default for SystemClock {
    fn default() -> Self {
        Self(std::time::Instant::now())
    }
}
impl Clock for SystemClock {
    fn milliseconds(&self) -> u64 {
        u64::try_from(self.0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}
