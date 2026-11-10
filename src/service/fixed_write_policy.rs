//! A fixed write policy for hosts that already checked their settings.

use std::convert::Infallible;

use crate::Availability;

use super::WritePolicy;

/// An explicit guarded policy for hosts that already checked their settings.
///
/// The service still calls `check` before writing, but this value is a fixed
/// snapshot. Prefer a settings-backed [`WritePolicy`] for long-lived servers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedWritePolicy {
    pub availability: Availability,
}

impl FixedWritePolicy {
    pub fn new(availability: Availability) -> Self {
        Self { availability }
    }

    pub fn available() -> Self {
        Self::new(Availability::available())
    }

    pub fn disabled(reason: impl Into<String>) -> Self {
        Self::new(Availability::disabled(reason))
    }
}

impl WritePolicy for FixedWritePolicy {
    type Error = Infallible;

    async fn check(&self) -> Result<Availability, Self::Error> {
        Ok(self.availability.clone())
    }
}
