//! Host-independent state exchanged by the SPF service and UI.

use std::net::{Ipv4Addr, Ipv6Addr};

/// IPv4/IPv6 addresses this feature last successfully published.
///
/// These are the addresses last confirmed in the provider's TXT RRset after a
/// successful read-back, not the addresses discovery returned and not a
/// history: a store keeps at most the latest IPv4 and IPv6 values per domain.
/// A verified update that discovered only one usable family clears the other
/// family instead of retaining its previous value. [`apply`](crate::apply)
/// saves them only after verification succeeds, so a failed discovery, lookup,
/// write or verification leaves the stored values unchanged.
///
/// The previous values identify exact `pass` host directives that may be
/// replaced or removed. They are not a general allow-list and are never
/// treated as authorization.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SpfAddresses {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

impl SpfAddresses {
    /// Build the values for the next update by replacing each family with what
    /// discovery found.
    ///
    /// A family that discovery did not provide is cleared, not carried over
    /// from `self`. Its previously applied host directive is therefore removed
    /// by the rewrite. The result is not published until `apply` has written
    /// and verified the record.
    pub fn replaced_with(self, discovered: DiscoveredAddresses) -> Self {
        Self {
            ipv4: discovered.ipv4,
            ipv6: discovered.ipv6,
        }
    }

    /// Compatibility alias for [`SpfAddresses::replaced_with`].
    ///
    /// An unavailable family is now cleared rather than retained, so this name
    /// is deprecated in favour of the explicit replacement method.
    #[deprecated(note = "use `SpfAddresses::replaced_with`; an unavailable family is now cleared")]
    pub fn merged_with(self, discovered: DiscoveredAddresses) -> Self {
        self.replaced_with(discovered)
    }

    pub fn is_empty(self) -> bool {
        self.ipv4.is_none() && self.ipv6.is_none()
    }
}

/// Public addresses discovered for the current host.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DiscoveredAddresses {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

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

#[cfg(test)]
mod tests {
    use super::{Availability, DiscoveredAddresses, SpfAddresses};

    fn address(value: &str) -> SpfAddresses {
        SpfAddresses {
            ipv4: Some(value.parse().expect("IPv4")),
            ipv6: None,
        }
    }

    #[test]
    fn replaced_with_clears_a_family_that_discovery_did_not_provide() {
        let applied = SpfAddresses {
            ipv4: Some("203.0.113.7".parse().expect("IPv4")),
            ipv6: Some("2001:db8::7".parse().expect("IPv6")),
        };

        assert_eq!(
            applied.replaced_with(DiscoveredAddresses {
                ipv4: Some("203.0.113.8".parse().expect("IPv4")),
                ipv6: None,
            }),
            address("203.0.113.8")
        );
        assert_eq!(
            applied.replaced_with(DiscoveredAddresses {
                ipv4: None,
                ipv6: Some("2001:db8::8".parse().expect("IPv6")),
            }),
            SpfAddresses {
                ipv4: None,
                ipv6: Some("2001:db8::8".parse().expect("IPv6")),
            }
        );
        assert!(
            applied
                .replaced_with(DiscoveredAddresses::default())
                .is_empty()
        );
    }

    #[test]
    fn refresh_and_write_require_spf_provider_and_write_policy() {
        for spf_enabled in [false, true] {
            for provider_enabled in [false, true] {
                for write_available in [false, true] {
                    let availability = Availability {
                        spf_enabled,
                        provider_enabled,
                        write_available,
                        reason: None,
                    };
                    assert_eq!(
                        availability.can_refresh(),
                        spf_enabled && provider_enabled,
                        "can_refresh for {availability:?}"
                    );
                    assert_eq!(
                        availability.can_write(),
                        spf_enabled && provider_enabled && write_available,
                        "can_write for {availability:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn constructors_keep_the_spf_setting_independent_of_the_provider() {
        let available = Availability::available();
        assert!(available.spf_enabled);
        assert!(available.provider_enabled);
        assert!(available.can_write());

        let spf_off = Availability::spf_disabled("SPF is off.");
        assert!(!spf_off.spf_enabled);
        assert!(spf_off.provider_enabled);
        assert!(!spf_off.can_refresh());
        assert!(!spf_off.can_write());

        let provider_off = Availability::provider_disabled(true, "Provider is off.");
        assert!(provider_off.spf_enabled);
        assert!(!provider_off.provider_enabled);
        assert!(!provider_off.can_refresh());
        assert!(!provider_off.can_write());

        let disabled = Availability::disabled("Everything is off.");
        assert!(!disabled.spf_enabled);
        assert!(!disabled.provider_enabled);
        assert!(!disabled.can_refresh());
        assert!(!disabled.can_write());
    }
}

/// A read-only view of the current and desired SPF state for a host page.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Snapshot {
    /// The DNS name whose TXT RRset was inspected, with surrounding whitespace
    /// trimmed.
    pub domain: String,
    /// Host-supplied label for where the current record was read from.
    pub source: String,
    /// The first SPF TXT value found, if any.
    pub current: Option<String>,
    /// The record that Apply would publish, or an empty string when it cannot
    /// be computed.
    pub desired: String,
    /// Public IPv4 address discovered for this host.
    pub public_ipv4: Option<Ipv4Addr>,
    /// Public IPv6 address discovered for this host.
    pub public_ipv6: Option<Ipv6Addr>,
    /// Addresses last confirmed as published by this feature.
    pub applied: SpfAddresses,
    /// The host's independent SPF enabled, provider enabled and write-policy
    /// state.
    pub availability: Availability,
    /// Whether the current record already contains the discovered public
    /// addresses. This is informational only: Apply is gated by
    /// [`Snapshot::needs_update`], because a record can contain the public
    /// addresses and still need a rewrite to remove a stale managed address.
    pub matches: bool,
    /// Whether applying would change the SPF TXT value.
    ///
    /// This is `false` when the desired value could not be computed or already
    /// equals the current SPF value. It reflects the value `apply` would write,
    /// so cosmetic differences in spelling or whitespace count as an update.
    pub needs_update: bool,
    /// Combined inspection, discovery, storage or record error text.
    pub error: Option<String>,
}

/// The domain and source label used for an inspection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectRequest {
    /// The domain to inspect. `inspect` and `apply` trim surrounding whitespace;
    /// hosts must still validate it.
    pub domain: String,
    /// For example, the DNS provider's name, or `authoritative DNS`.
    pub source: String,
}

impl InspectRequest {
    pub fn new(domain: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            source: source.into(),
        }
    }
}

/// The result of a successful, verified SPF update.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyResult {
    /// The SPF record that was written or confirmed.
    pub desired_record: String,
    /// Whether the TXT RRset changed.
    pub changed: bool,
    /// Addresses to retain as the latest successfully published values for the
    /// next update.
    pub applied: SpfAddresses,
    /// A host-presentable success message.
    pub message: String,
}
