//! Fixture-backed state for the runnable browser preview.
//!
//! The DNS record, previously applied addresses and public addresses are fixed
//! documentation fixtures. [`snapshot`] builds the proposed record and status
//! through the normal [`inspect`] service, so the preview exercises the same
//! rewrite rules as a host. It contacts no external services: public addresses
//! come from a local [`PublicAddressDiscovery`] implementation.
//!
//! Inspection is skipped when SPF or the provider is disabled, and the complete
//! inspection is bounded by [`DISCOVERY_TIMEOUT`]. [`Snapshot::public_ipv4`] and
//! [`Snapshot::public_ipv6`] contain the fixture public addresses. The preview's
//! Publish action is simulated in the example app; this module never writes DNS.
//! [`published_snapshot`] simulates the state after that Publish succeeds: the
//! fixture DNS record and last-applied addresses hold the proposed values, so
//! inspection reports Current and Proposed as equal.

use crate::{
    Availability, DiscoveredAddresses, FixedWritePolicy, InspectRequest, MemorySpfAddressStore,
    PublicAddressDiscovery, Snapshot, SpfAddresses, SpfDns, inspect,
};
use std::{convert::Infallible, time::Duration};

/// The fixture domain shown in the preview.
pub const DOMAIN: &str = "example.com";

/// The label shown as the snapshot source.
pub const SOURCE: &str = "Preview fixture (static DNS record)";

/// The one SPF TXT value the fixture DNS source returns before a simulated
/// Publish.
pub const CURRENT_RECORD: &str = "v=spf1 ip4:198.51.100.24 include:_spf.example.net -all";

/// Overall budget for the preview's fixture inspection.
pub const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);

/// The fixture's last successfully applied addresses.
///
/// These identify the previous `pass` host directives in [`CURRENT_RECORD`]
/// that an update may replace or remove. Only the IPv4 address is recorded
/// because the fixture record has no IPv6 directive.
pub fn applied() -> SpfAddresses {
    SpfAddresses {
        ipv4: Some("198.51.100.24".parse().expect("documentation IPv4")),
        ipv6: None,
    }
}

/// Which fixture state the preview should present.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum PreviewState {
    /// The fixture DNS record has not been published by the preview.
    #[default]
    Unpublished,
    /// A successful Publish is simulated: the fixture DNS record and
    /// last-applied addresses hold the values Publish proposed.
    Published,
}

/// Read-only fixture DNS source.
#[derive(Clone, Debug)]
struct FixtureDns {
    current: String,
}

impl FixtureDns {
    fn for_state(state: PreviewState) -> Self {
        Self {
            current: current_record(state),
        }
    }
}

impl SpfDns for FixtureDns {
    type Error = Infallible;

    async fn txt_records(&self, _name: &crate::DomainName) -> Result<Vec<String>, Self::Error> {
        Ok(vec![self.current.clone()])
    }

    async fn replace_txt_records(
        &self,
        _name: &crate::DomainName,
        _records: &[String],
    ) -> Result<(), Self::Error> {
        // `inspect` only reads. The preview's Publish handler never calls
        // `apply`, so no preview path reaches this method.
        Ok(())
    }
}

/// Public addresses supplied by the preview fixture.
///
/// The values use documentation ranges, so the preview never contacts a public
/// address service.
#[derive(Clone, Copy, Debug, Default)]
struct FixtureDiscovery;

impl PublicAddressDiscovery for FixtureDiscovery {
    type Error = Infallible;

    async fn discover(&self) -> Result<DiscoveredAddresses, Self::Error> {
        Ok(fixture_discovered())
    }
}

fn fixture_discovered() -> DiscoveredAddresses {
    DiscoveredAddresses {
        ipv4: Some("203.0.113.24".parse().expect("documentation IPv4")),
        ipv6: Some("2001:db8::24".parse().expect("documentation IPv6")),
    }
}

/// Build the preview snapshot using fixture public addresses.
///
/// Inspection and the fixture discovery share one [`DISCOVERY_TIMEOUT`]
/// budget. When SPF or the provider is disabled, inspection is skipped and the
/// snapshot keeps the fixture record and previous addresses with no proposed
/// value. A timeout or an inspection failure also leaves the proposed value
/// empty rather than presenting a fixture-only rewrite as an update.
pub async fn snapshot(availability: Availability) -> Snapshot {
    snapshot_for(availability, PreviewState::Unpublished).await
}

/// Build the preview snapshot after simulating a successful Publish.
///
/// The fixture DNS record and last-applied addresses are the values Publish
/// proposed. Running the normal [`inspect`] rewrite against them therefore
/// reports Current and Proposed as equal and clears [`Snapshot::needs_update`],
/// so the panel hides Proposed and disables Publish.
pub async fn published_snapshot(availability: Availability) -> Snapshot {
    snapshot_for(availability, PreviewState::Published).await
}

async fn snapshot_for(availability: Availability, state: PreviewState) -> Snapshot {
    snapshot_with(&FixtureDiscovery, availability, DISCOVERY_TIMEOUT, state).await
}

async fn snapshot_with<D>(
    discovery: &D,
    availability: Availability,
    timeout: Duration,
    state: PreviewState,
) -> Snapshot
where
    D: PublicAddressDiscovery,
{
    if !availability.can_refresh() {
        return fixture_snapshot(availability, None, state);
    }

    let dns = FixtureDns::for_state(state);
    let store = MemorySpfAddressStore::with_initial([(
        crate::DomainName::new(DOMAIN).unwrap(),
        applied_for_state(state),
    )]);
    let policy = FixedWritePolicy::new(availability.clone());
    let request = InspectRequest::new(crate::DomainName::new(DOMAIN).unwrap(), SOURCE);
    let inspection = inspect(&dns, discovery, &store, &policy, &request);

    match tokio::time::timeout(timeout, inspection).await {
        Ok(mut snapshot) => {
            if snapshot.public_ipv4.is_none() && snapshot.public_ipv6.is_none() {
                // No fixture address is usable. Keep the previous fixture
                // addresses visible in "last applied"; no update is proposed.
                snapshot.desired = None;
                snapshot.matches = false;
                snapshot.needs_update = false;
            }
            snapshot
        }
        Err(_) => fixture_snapshot(
            availability,
            Some(format!(
                "Fixture inspection did not finish within {timeout:?}. The static DNS fixture is shown and no public IP addresses were produced."
            )),
            state,
        ),
    }
}

/// Explain why a family is missing or why inspection was skipped.
///
/// The preview renders this as a neutral notice, leaving
/// [`Snapshot::error`] for actual inspection failures. Returns `None` when both
/// families are present.
pub fn discovery_note(snapshot: &Snapshot) -> Option<String> {
    if !snapshot.availability.can_refresh() {
        return Some(
            "Public address inspection was skipped because SPF or the DNS provider is disabled."
                .into(),
        );
    }

    match (snapshot.public_ipv4.is_some(), snapshot.public_ipv6.is_some()) {
        (true, true) => None,
        (false, false) => Some(
            "The preview fixture supplied no usable public address. No update is proposed and previously applied directives are left unchanged."
                .into(),
        ),
        (false, true) => Some(
            "No usable public IPv4 address was supplied; the proposed record removes the fixture's previously applied IPv4 directive if it has one."
                .into(),
        ),
        (true, false) => Some(
            "No usable public IPv6 address was supplied; the proposed record removes the fixture's previously applied IPv6 directive if it has one."
                .into(),
        ),
    }
}

/// A snapshot that does not present fixture values as an update.
///
/// Disabled snapshots keep the fixture readable but leave the proposed value
/// empty because inspection was intentionally skipped. A timeout also has no
/// proposal because no inspection completed.
fn fixture_snapshot(
    availability: Availability,
    error: Option<String>,
    state: PreviewState,
) -> Snapshot {
    Snapshot {
        domain: crate::DomainName::new(DOMAIN).unwrap(),
        source: SOURCE.into(),
        current: Some(current_record(state)),
        desired: None,
        public_ipv4: None,
        public_ipv6: None,
        applied: applied_for_state(state),
        availability,
        matches: false,
        needs_update: false,
        error,
    }
}

/// The fixture DNS value for a state.
fn current_record(state: PreviewState) -> String {
    match state {
        PreviewState::Unpublished => CURRENT_RECORD.to_owned(),
        PreviewState::Published => published_record(),
    }
}

/// The fixture record Publish proposes, used as the DNS value after publishing.
fn published_record() -> String {
    let discovered = fixture_discovered();
    crate::desired_spf_record(
        Some(CURRENT_RECORD),
        discovered.ipv4,
        discovered.ipv6,
        &applied(),
    )
    .expect("the fixture record can be rewritten")
    .into_string()
}

/// The last-applied addresses for a state. A simulated Publish saves the
/// addresses it published, clearing a family discovery did not provide.
fn applied_for_state(state: PreviewState) -> SpfAddresses {
    match state {
        PreviewState::Unpublished => applied(),
        PreviewState::Published => applied().replaced_with(fixture_discovered()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DiscoveredAddresses;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct FixedDiscovery(DiscoveredAddresses);

    impl PublicAddressDiscovery for FixedDiscovery {
        type Error = String;

        async fn discover(&self) -> Result<DiscoveredAddresses, Self::Error> {
            Ok(self.0)
        }
    }

    struct FailingDiscovery;

    impl PublicAddressDiscovery for FailingDiscovery {
        type Error = String;

        async fn discover(&self) -> Result<DiscoveredAddresses, Self::Error> {
            Err("simulated discovery failure".into())
        }
    }

    struct CountingDiscovery {
        result: DiscoveredAddresses,
        calls: Arc<AtomicUsize>,
    }

    impl CountingDiscovery {
        fn new(result: DiscoveredAddresses) -> (Self, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    result,
                    calls: Arc::clone(&calls),
                },
                calls,
            )
        }
    }

    impl PublicAddressDiscovery for CountingDiscovery {
        type Error = String;

        async fn discover(&self) -> Result<DiscoveredAddresses, Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.result)
        }
    }

    struct PendingDiscovery;

    impl PublicAddressDiscovery for PendingDiscovery {
        type Error = String;

        async fn discover(&self) -> Result<DiscoveredAddresses, Self::Error> {
            std::future::pending::<()>().await;
            unreachable!("pending discovery never resolves")
        }
    }

    fn ipv4(value: &str) -> std::net::Ipv4Addr {
        value.parse().expect("valid IPv4")
    }

    fn ipv6(value: &str) -> std::net::Ipv6Addr {
        value.parse().expect("valid IPv6")
    }

    fn discovered(
        ipv4: Option<std::net::Ipv4Addr>,
        ipv6: Option<std::net::Ipv6Addr>,
    ) -> DiscoveredAddresses {
        DiscoveredAddresses { ipv4, ipv6 }
    }

    async fn inspect_with(discovery: &impl PublicAddressDiscovery) -> Snapshot {
        snapshot_with(
            discovery,
            Availability::available(),
            Duration::from_secs(1),
            PreviewState::Unpublished,
        )
        .await
    }

    #[tokio::test]
    async fn default_snapshot_uses_fixture_addresses_without_external_services() {
        let snapshot = snapshot(Availability::available()).await;

        assert_eq!(snapshot.public_ipv4, Some(ipv4("203.0.113.24")));
        assert_eq!(snapshot.public_ipv6, Some(ipv6("2001:db8::24")));
        assert_eq!(
            snapshot.desired.as_deref(),
            Some("v=spf1 ip4:203.0.113.24 ip6:2001:db8::24 include:_spf.example.net -all")
        );
        assert!(snapshot.needs_update);
        assert!(snapshot.error.is_none());
        assert!(discovery_note(&snapshot).is_none());
    }

    #[tokio::test]
    async fn full_fixture_discovery_uses_supplied_addresses_and_the_library_rewrite() {
        let snapshot = inspect_with(&FixedDiscovery(discovered(
            Some(ipv4("203.0.113.24")),
            Some(ipv6("2001:db8::24")),
        )))
        .await;

        assert_eq!(snapshot.public_ipv4, Some(ipv4("203.0.113.24")));
        assert_eq!(snapshot.public_ipv6, Some(ipv6("2001:db8::24")));
        assert_eq!(snapshot.applied, applied());
        assert_eq!(
            snapshot.desired.as_deref(),
            Some("v=spf1 ip4:203.0.113.24 ip6:2001:db8::24 include:_spf.example.net -all")
        );
        assert!(snapshot.needs_update);
        assert!(!snapshot.matches);
        assert!(snapshot.error.is_none());
        assert!(discovery_note(&snapshot).is_none());
    }

    #[tokio::test]
    async fn published_snapshot_reports_current_and_proposed_equal() {
        let snapshot = published_snapshot(Availability::available()).await;
        let published = "v=spf1 ip4:203.0.113.24 ip6:2001:db8::24 include:_spf.example.net -all";

        assert_eq!(snapshot.current.as_deref(), Some(published));
        assert_eq!(snapshot.desired.as_deref(), Some(published));
        assert!(!snapshot.needs_update);
        assert!(snapshot.matches);
        assert_eq!(
            snapshot.applied,
            applied().replaced_with(fixture_discovered())
        );
        assert!(snapshot.error.is_none());
    }

    #[tokio::test]
    async fn partial_discovery_reports_and_removes_the_missing_family() {
        let snapshot = inspect_with(&FixedDiscovery(discovered(
            Some(ipv4("203.0.113.24")),
            None,
        )))
        .await;

        assert_eq!(snapshot.public_ipv4, Some(ipv4("203.0.113.24")));
        assert_eq!(snapshot.public_ipv6, None);
        assert_eq!(
            snapshot.desired.as_deref(),
            Some("v=spf1 ip4:203.0.113.24 include:_spf.example.net -all")
        );
        assert!(
            discovery_note(&snapshot)
                .expect("missing IPv6 is explained")
                .contains("IPv6")
        );

        let snapshot = inspect_with(&FixedDiscovery(discovered(
            None,
            Some(ipv6("2001:db8::24")),
        )))
        .await;

        assert_eq!(snapshot.public_ipv4, None);
        assert_eq!(snapshot.public_ipv6, Some(ipv6("2001:db8::24")));
        // The missing family removes the fixture's last-applied IPv4 directive.
        assert_eq!(
            snapshot.desired.as_deref(),
            Some("v=spf1 ip6:2001:db8::24 include:_spf.example.net -all")
        );
        assert!(
            discovery_note(&snapshot)
                .expect("missing IPv4 is explained")
                .contains("removes")
        );
    }

    #[tokio::test]
    async fn matching_and_empty_discovery_do_not_invent_addresses() {
        let snapshot = inspect_with(&FixedDiscovery(discovered(
            Some(ipv4("198.51.100.24")),
            None,
        )))
        .await;

        assert_eq!(snapshot.public_ipv4, Some(ipv4("198.51.100.24")));
        assert_eq!(snapshot.public_ipv6, None);
        assert_eq!(snapshot.desired.as_deref(), Some(CURRENT_RECORD));
        assert!(!snapshot.needs_update);
        assert!(snapshot.matches);
        assert!(snapshot.error.is_none());

        let snapshot = inspect_with(&FixedDiscovery(discovered(None, None))).await;
        assert_eq!(snapshot.public_ipv4, None);
        assert_eq!(snapshot.public_ipv6, None);
        assert!(snapshot.desired.is_none());
        assert!(!snapshot.needs_update);
        assert!(!snapshot.matches);
        assert!(snapshot.error.is_none());
        assert!(
            discovery_note(&snapshot)
                .expect("empty discovery is explained")
                .contains("no usable public address")
        );
    }

    #[tokio::test]
    async fn discovery_failure_keeps_the_fixture_readable_without_a_proposal() {
        let snapshot = inspect_with(&FailingDiscovery).await;

        assert_eq!(snapshot.current.as_deref(), Some(CURRENT_RECORD));
        assert_eq!(snapshot.applied, applied());
        assert_eq!(snapshot.public_ipv4, None);
        assert_eq!(snapshot.public_ipv6, None);
        assert!(snapshot.desired.is_none());
        assert!(!snapshot.needs_update);
        assert!(
            snapshot
                .error
                .as_deref()
                .expect("discovery error is shown")
                .contains("simulated discovery failure")
        );
    }

    #[tokio::test]
    async fn timeout_reports_the_budget_and_does_not_propose_a_record() {
        let snapshot = snapshot_with(
            &PendingDiscovery,
            Availability::available(),
            Duration::from_millis(10),
            PreviewState::Unpublished,
        )
        .await;

        assert_eq!(snapshot.current.as_deref(), Some(CURRENT_RECORD));
        assert_eq!(snapshot.applied, applied());
        assert_eq!(snapshot.public_ipv4, None);
        assert_eq!(snapshot.public_ipv6, None);
        assert!(snapshot.desired.is_none());
        assert!(!snapshot.needs_update);
        assert!(
            snapshot
                .error
                .as_deref()
                .expect("timeout is shown")
                .contains("did not finish within")
        );
    }

    #[tokio::test]
    async fn disabled_availability_skips_address_inspection() {
        let (discovery, calls) = CountingDiscovery::new(discovered(
            Some(ipv4("203.0.113.24")),
            Some(ipv6("2001:db8::24")),
        ));
        let snapshot = snapshot_with(
            &discovery,
            Availability::spf_disabled("SPF is disabled."),
            Duration::from_secs(1),
            PreviewState::Unpublished,
        )
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(snapshot.current.as_deref(), Some(CURRENT_RECORD));
        assert_eq!(snapshot.applied, applied());
        assert_eq!(snapshot.public_ipv4, None);
        assert_eq!(snapshot.public_ipv6, None);
        assert!(snapshot.desired.is_none());
        assert!(snapshot.error.is_none());
        assert!(
            discovery_note(&snapshot)
                .expect("skipped discovery is explained")
                .contains("skipped")
        );

        let (discovery, calls) = CountingDiscovery::new(discovered(None, None));
        let snapshot = snapshot_with(
            &discovery,
            Availability::provider_disabled(true, "The DNS provider is disabled."),
            Duration::from_secs(1),
            PreviewState::Unpublished,
        )
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(snapshot.availability.spf_enabled);
        assert!(!snapshot.availability.provider_enabled);
        assert!(snapshot.desired.is_none());
        assert!(snapshot.error.is_none());
    }
}
