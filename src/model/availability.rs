//! Host state that controls SPF refresh and writes.

/// Non-secret host state that controls SPF refresh, writes and the UI controls.
///
/// `spf_enabled` mirrors the host's saved SPF enabled setting. It is the only
/// state controlled by the panel's Enable switch.
/// `provider_enabled` mirrors the saved DNS provider enabled flag, which the
/// host maintains separately. When it is false, all SPF controls, including the
/// Enable switch, are disabled.
/// `write_available` lets a host add its own policy, such as missing
/// credentials, maintenance mode or a read-only replica.
///
/// Refresh requires `spf_enabled` and `provider_enabled`. Writes additionally
/// require `write_available`. The service enforces the same conditions so a
/// disabled setting cannot be bypassed by omitting the UI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Availability {
    pub spf_enabled: bool,
    pub provider_enabled: bool,
    pub write_available: bool,
    pub reason: Option<String>,
}

impl Availability {
    /// SPF and the provider are enabled and the host permits writes.
    pub fn available() -> Self {
        Self {
            spf_enabled: true,
            provider_enabled: true,
            write_available: true,
            reason: None,
        }
    }

    /// Every SPF control is unavailable and the reason can be shown to the
    /// operator. This is the safe default and the state for an unreadable or
    /// unconfigured settings source.
    pub fn disabled(reason: impl Into<String>) -> Self {
        Self {
            spf_enabled: false,
            provider_enabled: false,
            write_available: false,
            reason: Some(reason.into()),
        }
    }

    /// SPF is turned off in its own setting while the provider remains
    /// available. The Enable switch stays usable so the operator can turn SPF
    /// back on.
    pub fn spf_disabled(reason: impl Into<String>) -> Self {
        Self {
            spf_enabled: false,
            provider_enabled: true,
            write_available: true,
            reason: Some(reason.into()),
        }
    }

    /// The DNS provider is disabled. `spf_enabled` preserves the saved SPF
    /// setting so the switch can display it, but every SPF control is disabled.
    pub fn provider_disabled(spf_enabled: bool, reason: impl Into<String>) -> Self {
        Self {
            spf_enabled,
            provider_enabled: false,
            write_available: true,
            reason: Some(reason.into()),
        }
    }

    /// Refresh is allowed only when SPF and the provider are both enabled.
    pub fn can_refresh(&self) -> bool {
        self.spf_enabled && self.provider_enabled
    }

    /// Writes require SPF and the provider to be enabled and the host to allow
    /// writes.
    pub fn can_write(&self) -> bool {
        self.can_refresh() && self.write_available
    }
}

impl Default for Availability {
    /// The safe default is unavailable; hosts must opt in explicitly.
    fn default() -> Self {
        Self::disabled("SPF updates are unavailable. Enable SPF and the DNS provider.")
    }
}
