//! Host-independent state exchanged by the SPF service and UI.

mod apply_result;
mod availability;
mod discovered_addresses;
mod inspect_request;
mod snapshot;
mod spf_addresses;

pub use apply_result::ApplyResult;
pub use availability::Availability;
pub use discovered_addresses::DiscoveredAddresses;
pub use inspect_request::InspectRequest;
pub use snapshot::Snapshot;
pub use spf_addresses::SpfAddresses;

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

mod validated;
pub use validated::{DomainName, DomainNameError, SpfRecordText, UsablePublicAddresses};
