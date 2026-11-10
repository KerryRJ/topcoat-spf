//! Async, trait-decoupled SPF inspection and update service.
//!
//! The crate owns SPF parsing and rewriting. The host owns DNS, public-address
//! discovery, applied-address persistence and the settings-backed write policy.
//! Public traits return `Send` futures so the service can be used from
//! multithreaded async servers; implementations should use `async fn` where
//! their generated futures are `Send`.

use crate::{
    ApplyResult, Availability, DiscoveredAddresses, InspectRequest, Snapshot, SpfAddresses,
    SpfError,
    spf::{
        desired_spf_record, is_public_ipv4, is_public_ipv6, is_spf,
        record_matches_public_addresses, records_equivalent, replace_txt_records,
    },
};
use std::{collections::HashMap, convert::Infallible, fmt::Display, future::Future, sync::Mutex};

/// Narrow asynchronous TXT capability required by the SPF service.
///
/// Only TXT reads and full-RRset replacement are exposed. Provider credentials,
/// zones, TTLs, authorization and record types other than TXT remain the host's
/// concern. `replace_txt_records` receives the complete intended TXT RRset,
/// including unrelated values the caller wants to preserve, and must replace the
/// TXT RRset with exactly those values. Values of other record types are
/// unaffected.
pub trait SpfDns: Send + Sync {
    type Error: Display + Send + Sync + 'static;

    /// Return every TXT value at `name`, or an empty vector when none exist.
    fn txt_records(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Vec<String>, Self::Error>> + Send;

    /// Replace the complete TXT RRset at `name` with `records`.
    ///
    /// Implementations should use one provider call when available. When the
    /// provider only supports additions and removals, a partial failure may
    /// leave the RRset temporarily changed; see the crate README.
    fn replace_txt_records(
        &self,
        name: &str,
        records: &[String],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// Asynchronous persistence for the IPv4/IPv6 addresses this feature last
/// successfully published.
///
/// A store holds at most the latest published IPv4 and IPv6 values per domain.
/// It is neither a record of discovered addresses nor a history of past
/// values. [`apply`] saves only after the provider read-back verifies the
/// complete expected TXT set; a failed discovery, lookup, write or verification
/// leaves the stored values unchanged.
///
/// The host chooses the database, tenant scope and authorization model. These
/// addresses are operational state, not authorization: a missing or stale
/// value must never allow a host to bypass its own access checks.
pub trait SpfAddressStore: Send + Sync {
    type Error: Display + Send + Sync + 'static;

    /// Return the last successfully published addresses for `domain`, or an
    /// empty value when none have been stored.
    fn load(&self, domain: &str) -> impl Future<Output = Result<SpfAddresses, Self::Error>> + Send;

    /// Persist `addresses` as the latest successfully published values for
    /// `domain`.
    fn save(
        &self,
        domain: &str,
        addresses: &SpfAddresses,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// Settings-backed seam re-read before an update and again before a DNS write.
///
/// Implement this over the host's own SPF and DNS provider settings. Return
/// only non-secret availability state, including the saved SPF enabled flag
/// ([`Availability::spf_enabled`]) and provider enabled flag
/// ([`Availability::provider_enabled`]) as independent values. The SPF service
/// calls `check` at the start of `apply` and immediately before any write, so
/// disabling either setting in storage stops a pending update in the common
/// case. This is not a distributed lock: a concurrent settings change after the
/// final check can still race with the provider request.
pub trait WritePolicy: Send + Sync {
    type Error: Display + Send + Sync + 'static;

    fn check(&self) -> impl Future<Output = Result<Availability, Self::Error>> + Send;
}

/// Asynchronous public IPv4/IPv6 discovery.
///
/// Discovery is separate from DNS writes so hosts can supply their own
/// mechanism or a deterministic test implementation.
pub trait PublicAddressDiscovery: Send + Sync {
    type Error: Display + Send + Sync + 'static;

    fn discover(&self) -> impl Future<Output = Result<DiscoveredAddresses, Self::Error>> + Send;
}

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

/// A reusable in-memory last-published-address store for examples, previews
/// and tests.
///
/// Values are process-local and are discarded when the store is dropped.
#[derive(Default)]
pub struct MemorySpfAddressStore {
    values: Mutex<HashMap<String, SpfAddresses>>,
}

impl MemorySpfAddressStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_initial(values: impl IntoIterator<Item = (String, SpfAddresses)>) -> Self {
        Self {
            values: Mutex::new(values.into_iter().collect()),
        }
    }

    pub fn snapshot(&self) -> HashMap<String, SpfAddresses> {
        self.values
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }
}

impl SpfAddressStore for MemorySpfAddressStore {
    type Error = Infallible;

    async fn load(&self, domain: &str) -> Result<SpfAddresses, Self::Error> {
        Ok(self
            .values
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(domain)
            .copied()
            .unwrap_or_default())
    }

    async fn save(&self, domain: &str, addresses: &SpfAddresses) -> Result<(), Self::Error> {
        self.values
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(domain.to_owned(), *addresses);
        Ok(())
    }
}

/// Inspect the current record and build the desired one without writing.
///
/// This is intentionally resilient: discovery, storage, policy and DNS errors
/// are collected into [`Snapshot::error`] so the page can still render what is
/// known. The desired value uses only the usable discovered families: a family
/// that discovery did not provide is not carried over from the stored applied
/// addresses, so its previously managed directive is removed from the proposal.
/// When neither family is usable, [`Snapshot::desired`] is empty and no rewrite
/// is proposed. The host should re-check its own authorization before exposing
/// the snapshot, and must not treat a snapshot as permission to write.
pub async fn inspect<D, A, S, P>(
    dns: &D,
    discovery: &A,
    store: &S,
    policy: &P,
    request: &InspectRequest,
) -> Snapshot
where
    D: SpfDns,
    A: PublicAddressDiscovery,
    S: SpfAddressStore,
    P: WritePolicy,
{
    let domain = request.domain.trim();
    let mut error = None;
    let availability = match policy.check().await {
        Ok(availability) => availability,
        Err(policy_error) => {
            let reason = format!("SPF and provider settings could not be read: {policy_error}");
            append_error(&mut error, reason.clone());
            Availability::disabled(reason)
        }
    };
    let discovered = match discovery.discover().await {
        Ok(discovered) => public_discovered(discovered),
        Err(discovery_error) => {
            append_error(
                &mut error,
                format!("Public address discovery failed: {discovery_error}"),
            );
            DiscoveredAddresses::default()
        }
    };
    let applied = match store.load(domain).await {
        Ok(applied) => applied,
        Err(store_error) => {
            append_error(
                &mut error,
                format!("Applied addresses could not be loaded: {store_error}"),
            );
            SpfAddresses::default()
        }
    };

    let mut current = None;
    if domain.is_empty() {
        append_error(&mut error, "Set a domain before inspecting SPF.");
    } else {
        match dns.txt_records(domain).await {
            Ok(records) => {
                let spf: Vec<_> = records
                    .into_iter()
                    .filter(|record| is_spf(record))
                    .collect();
                current = spf.first().cloned();
                if spf.len() > 1 {
                    append_error(
                        &mut error,
                        "Multiple SPF TXT records were returned; SPF requires a single record.",
                    );
                }
            }
            Err(dns_error) => {
                append_error(&mut error, format!("DNS TXT lookup failed: {dns_error}"));
            }
        }
    }

    let next = applied.replaced_with(discovered);
    let desired = if next.is_empty() {
        // With no usable family, an update must not remove every managed
        // directive. `apply` refuses the same state with NoDiscoveredAddress.
        String::new()
    } else {
        desired_spf_record(current.as_deref(), next.ipv4, next.ipv6, &applied).unwrap_or_else(
            |record_error| {
                append_error(&mut error, record_error.to_string());
                String::new()
            },
        )
    };
    let matches =
        record_matches_public_addresses(current.as_deref(), discovered.ipv4, discovered.ipv6);
    // `apply` compares the complete TXT RRset, but unrelated values are preserved
    // by construction, so the SPF value alone determines whether it writes.
    let needs_update = !desired.is_empty() && current.as_deref() != Some(desired.as_str());

    Snapshot {
        domain: domain.to_owned(),
        source: request.source.clone(),
        current,
        desired,
        public_ipv4: discovered.ipv4,
        public_ipv6: discovered.ipv6,
        applied,
        availability,
        matches,
        needs_update,
        error,
    }
}

/// Discover addresses, rewrite the SPF value, write it, verify it by reading it
/// back, and save the last successfully published addresses.
///
/// A family that discovery does not provide is cleared: the rewrite removes its
/// previously applied host directive, and the saved addresses no longer contain
/// that family. When neither family is available, this returns
/// [`SpfError::NoDiscoveredAddress`] before reading or writing DNS and before
/// changing stored addresses. The host must authorize the caller and serialize
/// updates per domain before invoking this function. See the crate README for
/// the exact ordering and its non-atomic failure modes.
pub async fn apply<D, S, A, P>(
    dns: &D,
    store: &S,
    discovery: &A,
    policy: &P,
    domain: &str,
) -> Result<ApplyResult, SpfError>
where
    D: SpfDns,
    S: SpfAddressStore,
    A: PublicAddressDiscovery,
    P: WritePolicy,
{
    ensure_write_allowed(
        policy
            .check()
            .await
            .map_err(|error| SpfError::Policy(error.to_string()))?,
    )?;
    let domain = domain.trim();
    if domain.is_empty() {
        return Err(SpfError::NoDomain);
    }

    let discovered = public_discovered(
        discovery
            .discover()
            .await
            .map_err(|error| SpfError::Discovery(error.to_string()))?,
    );
    if discovered.ipv4.is_none() && discovered.ipv6.is_none() {
        return Err(SpfError::NoDiscoveredAddress);
    }
    let applied = store
        .load(domain)
        .await
        .map_err(|error| SpfError::LoadApplied(error.to_string()))?;
    let next = applied.replaced_with(discovered);

    let original = dns
        .txt_records(domain)
        .await
        .map_err(|error| SpfError::Lookup(error.to_string()))?;
    let rewrite = replace_txt_records(&original, next.ipv4, next.ipv6, &applied)?;
    let changed = !records_equivalent(&original, &rewrite.records);

    if changed {
        // Re-read the host's settings immediately before the provider write.
        ensure_write_allowed(
            policy
                .check()
                .await
                .map_err(|error| SpfError::Policy(error.to_string()))?,
        )?;
        dns.replace_txt_records(domain, &rewrite.records)
            .await
            .map_err(|error| SpfError::Write(error.to_string()))?;
    }

    let confirmed = dns
        .txt_records(domain)
        .await
        .map_err(|error| SpfError::VerificationLookup(error.to_string()))?;
    if !records_equivalent(&rewrite.records, &confirmed) {
        return Err(SpfError::Verification);
    }

    store
        .save(domain, &next)
        .await
        .map_err(|error| SpfError::SaveApplied(error.to_string()))?;

    Ok(ApplyResult {
        desired_record: rewrite.desired,
        changed,
        applied: next,
        message: if changed {
            "SPF updated and verified with the DNS provider. Addresses saved.".into()
        } else {
            "The DNS provider already has the desired SPF record. Addresses saved.".into()
        },
    })
}

/// Drop addresses that must never be published in SPF.
///
/// A non-public family is treated as unavailable, so the rewrite removes its
/// previously applied host directive and clears the family from the saved
/// addresses. This deliberately cannot distinguish a transient discovery
/// failure or a non-public result from a genuinely unavailable family; see
/// [`PublicAddressDiscovery`] and the crate README.
fn public_discovered(discovered: DiscoveredAddresses) -> DiscoveredAddresses {
    DiscoveredAddresses {
        ipv4: discovered.ipv4.filter(|ip| is_public_ipv4(*ip)),
        ipv6: discovered.ipv6.filter(|ip| is_public_ipv6(*ip)),
    }
}

fn ensure_write_allowed(availability: Availability) -> Result<(), SpfError> {
    if availability.can_write() {
        return Ok(());
    }

    Err(SpfError::WriteUnavailable(
        availability.reason.unwrap_or_else(|| {
            if !availability.provider_enabled {
                "Enable and configure the DNS provider before applying SPF changes.".into()
            } else if !availability.spf_enabled {
                "Enable SPF before applying changes.".into()
            } else {
                "The host's write policy does not currently allow SPF changes.".into()
            }
        }),
    ))
}

fn append_error(error: &mut Option<String>, message: impl Into<String>) {
    let message = message.into();
    *error = Some(match error.take() {
        Some(existing) => format!("{existing} {message}"),
        None => message,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spf::is_spf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone, Copy)]
    enum ReplaceBehavior {
        Store,
        StoreWrong,
    }

    struct FakeDnsState {
        records: Vec<String>,
        behavior: ReplaceBehavior,
    }

    struct FakeDns {
        state: Mutex<FakeDnsState>,
        lists: AtomicUsize,
        writes: AtomicUsize,
        names: Mutex<Vec<String>>,
    }

    impl FakeDns {
        fn new(records: &[&str]) -> Self {
            Self::with_behavior(records, ReplaceBehavior::Store)
        }

        fn with_behavior(records: &[&str], behavior: ReplaceBehavior) -> Self {
            Self {
                state: Mutex::new(FakeDnsState {
                    records: records.iter().map(|record| (*record).to_owned()).collect(),
                    behavior,
                }),
                lists: AtomicUsize::new(0),
                writes: AtomicUsize::new(0),
                names: Mutex::new(Vec::new()),
            }
        }

        fn records(&self) -> Vec<String> {
            self.state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .records
                .clone()
        }

        fn list_count(&self) -> usize {
            self.lists.load(Ordering::SeqCst)
        }

        fn write_count(&self) -> usize {
            self.writes.load(Ordering::SeqCst)
        }

        fn queried_names(&self) -> Vec<String> {
            self.names
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .clone()
        }
    }

    impl SpfDns for FakeDns {
        type Error = String;

        async fn txt_records(&self, name: &str) -> Result<Vec<String>, Self::Error> {
            self.lists.fetch_add(1, Ordering::SeqCst);
            self.names
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(name.to_owned());
            Ok(self.records())
        }

        async fn replace_txt_records(
            &self,
            _name: &str,
            records: &[String],
        ) -> Result<(), Self::Error> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            match state.behavior {
                ReplaceBehavior::Store => state.records = records.to_vec(),
                ReplaceBehavior::StoreWrong => {
                    state.records = vec!["v=spf1 -all".to_string()];
                }
            }
            Ok(())
        }
    }

    struct FakeDiscovery(DiscoveredAddresses);

    impl PublicAddressDiscovery for FakeDiscovery {
        type Error = String;

        async fn discover(&self) -> Result<DiscoveredAddresses, Self::Error> {
            Ok(self.0)
        }
    }

    struct CountingPolicy {
        checks: AtomicUsize,
        available_checks: usize,
    }

    impl CountingPolicy {
        fn new(available_checks: usize) -> Self {
            Self {
                checks: AtomicUsize::new(0),
                available_checks,
            }
        }

        fn checks(&self) -> usize {
            self.checks.load(Ordering::SeqCst)
        }
    }

    impl WritePolicy for CountingPolicy {
        type Error = String;

        async fn check(&self) -> Result<Availability, Self::Error> {
            let index = self.checks.fetch_add(1, Ordering::SeqCst);
            if index < self.available_checks {
                Ok(Availability::available())
            } else {
                Ok(Availability::disabled("The DNS provider is disabled."))
            }
        }
    }

    struct FailingStore;

    impl SpfAddressStore for FailingStore {
        type Error = String;

        async fn load(&self, _domain: &str) -> Result<SpfAddresses, Self::Error> {
            Ok(SpfAddresses::default())
        }

        async fn save(&self, _domain: &str, _addresses: &SpfAddresses) -> Result<(), Self::Error> {
            Err("storage offline".into())
        }
    }

    fn public_discovery() -> FakeDiscovery {
        FakeDiscovery(DiscoveredAddresses {
            ipv4: Some("203.0.113.8".parse().unwrap()),
            ipv6: Some("2001:db8::8".parse().unwrap()),
        })
    }

    fn request() -> InspectRequest {
        InspectRequest::new("example.com", "Test provider")
    }

    #[tokio::test]
    async fn inspect_reports_current_desired_and_match() {
        let dns = FakeDns::new(&["v=spf1 ip4:8.8.8.7 include:example.com ~all"]);
        let discovery = FakeDiscovery(DiscoveredAddresses {
            ipv4: Some("8.8.8.7".parse().unwrap()),
            ipv6: None,
        });
        let store = MemorySpfAddressStore::new();
        let policy = CountingPolicy::new(1);
        let snapshot = inspect(&dns, &discovery, &store, &policy, &request()).await;
        assert_eq!(snapshot.domain, "example.com");
        assert_eq!(snapshot.source, "Test provider");
        assert_eq!(
            snapshot.current.as_deref(),
            Some("v=spf1 ip4:8.8.8.7 include:example.com ~all")
        );
        assert_eq!(
            snapshot.desired,
            "v=spf1 ip4:8.8.8.7 include:example.com ~all"
        );
        assert!(snapshot.matches);
        assert!(!snapshot.needs_update);
        assert!(snapshot.availability.can_write());
        assert_eq!(snapshot.error, None);
        assert_eq!(policy.checks(), 1);
    }

    #[tokio::test]
    async fn inspect_collects_errors_and_keeps_the_first_spf_record() {
        let dns = FakeDns::new(&["verification=keep", "v=spf1 -all", "v=spf1 ~all"]);
        let snapshot = inspect(
            &dns,
            &public_discovery(),
            &MemorySpfAddressStore::new(),
            &CountingPolicy::new(1),
            &request(),
        )
        .await;
        assert_eq!(snapshot.current.as_deref(), Some("v=spf1 -all"));
        assert!(
            snapshot
                .error
                .as_deref()
                .is_some_and(|error| error.contains("Multiple SPF TXT records"))
        );
        assert!(!snapshot.matches);
    }

    #[tokio::test]
    async fn inspect_reports_disabled_provider_state() {
        let dns = FakeDns::new(&["v=spf1 -all"]);
        let snapshot = inspect(
            &dns,
            &public_discovery(),
            &MemorySpfAddressStore::new(),
            &CountingPolicy::new(0),
            &request(),
        )
        .await;
        assert!(!snapshot.availability.can_write());
        assert!(!snapshot.availability.provider_enabled);
        assert!(snapshot.availability.reason.is_some());
    }

    #[tokio::test]
    async fn inspect_reports_spf_and_provider_states_independently() {
        let spf_off = FixedWritePolicy::new(Availability::spf_disabled("SPF is off."));
        let snapshot = inspect(
            &FakeDns::new(&["v=spf1 -all"]),
            &public_discovery(),
            &MemorySpfAddressStore::new(),
            &spf_off,
            &request(),
        )
        .await;
        assert!(!snapshot.availability.spf_enabled);
        assert!(snapshot.availability.provider_enabled);
        assert!(!snapshot.availability.can_refresh());
        assert!(!snapshot.availability.can_write());

        let provider_off =
            FixedWritePolicy::new(Availability::provider_disabled(true, "Provider is off."));
        let snapshot = inspect(
            &FakeDns::new(&["v=spf1 -all"]),
            &public_discovery(),
            &MemorySpfAddressStore::new(),
            &provider_off,
            &request(),
        )
        .await;
        assert!(snapshot.availability.spf_enabled);
        assert!(!snapshot.availability.provider_enabled);
        assert!(!snapshot.availability.can_refresh());
        assert!(!snapshot.availability.can_write());
    }

    #[tokio::test]
    async fn inspect_treats_non_public_discovered_addresses_as_unavailable() {
        let dns = FakeDns::new(&["v=spf1 ip4:8.8.8.7 -all"]);
        let store = MemorySpfAddressStore::with_initial([(
            "example.com".to_string(),
            SpfAddresses {
                ipv4: Some("8.8.8.7".parse().unwrap()),
                ipv6: None,
            },
        )]);
        let discovery = FakeDiscovery(DiscoveredAddresses {
            ipv4: Some("192.168.1.2".parse().unwrap()),
            ipv6: Some("2001:db8::8".parse().unwrap()),
        });
        let snapshot = inspect(
            &dns,
            &discovery,
            &store,
            &CountingPolicy::new(1),
            &request(),
        )
        .await;
        assert_eq!(snapshot.public_ipv4, None);
        assert_eq!(snapshot.public_ipv6, Some("2001:db8::8".parse().unwrap()));
        assert_eq!(snapshot.desired, "v=spf1 ip6:2001:db8::8 -all");
        assert!(snapshot.error.is_none());
    }

    #[tokio::test]
    async fn inspect_and_apply_propose_the_same_partial_discovery_rewrite() {
        let dns = FakeDns::new(&[
            "verification=keep",
            "v=spf1 ip4:8.8.8.7 ip6:2001:db8::7 include:example.com -all",
        ]);
        let store = MemorySpfAddressStore::with_initial([(
            "example.com".to_string(),
            SpfAddresses {
                ipv4: Some("8.8.8.7".parse().unwrap()),
                ipv6: Some("2001:db8::7".parse().unwrap()),
            },
        )]);
        let discovery = FakeDiscovery(DiscoveredAddresses {
            ipv4: Some("9.9.9.9".parse().unwrap()),
            ipv6: None,
        });
        let snapshot = inspect(
            &dns,
            &discovery,
            &store,
            &CountingPolicy::new(1),
            &request(),
        )
        .await;
        assert_eq!(
            snapshot.desired,
            "v=spf1 ip4:9.9.9.9 include:example.com -all"
        );
        assert!(snapshot.needs_update);
        assert!(snapshot.error.is_none());

        let result = apply(
            &dns,
            &store,
            &discovery,
            &CountingPolicy::new(2),
            "example.com",
        )
        .await
        .unwrap();
        assert_eq!(result.desired_record, snapshot.desired);
        assert_eq!(
            dns.records(),
            vec![
                "verification=keep".to_string(),
                "v=spf1 ip4:9.9.9.9 include:example.com -all".to_string()
            ]
        );
        assert_eq!(
            result.applied,
            SpfAddresses {
                ipv4: Some("9.9.9.9".parse().unwrap()),
                ipv6: None,
            }
        );
        assert_eq!(store.snapshot().get("example.com"), Some(&result.applied));
    }

    #[tokio::test]
    async fn apply_removes_the_saved_ipv6_family_when_only_ipv4_is_discovered() {
        let dns =
            FakeDns::new(&["v=spf1 ip4:203.0.113.7 ip6:2001:db8::7 include:example.com -all"]);
        let store = MemorySpfAddressStore::with_initial([(
            "example.com".to_string(),
            SpfAddresses {
                ipv4: Some("203.0.113.7".parse().unwrap()),
                ipv6: Some("2001:db8::7".parse().unwrap()),
            },
        )]);
        let discovery = FakeDiscovery(DiscoveredAddresses {
            ipv4: Some("203.0.113.8".parse().unwrap()),
            ipv6: None,
        });
        let result = apply(
            &dns,
            &store,
            &discovery,
            &CountingPolicy::new(2),
            "example.com",
        )
        .await
        .unwrap();
        assert!(result.changed);
        assert_eq!(
            result.desired_record,
            "v=spf1 ip4:203.0.113.8 include:example.com -all"
        );
        assert_eq!(result.applied.ipv4, Some("203.0.113.8".parse().unwrap()));
        assert_eq!(result.applied.ipv6, None);
        assert_eq!(
            dns.records(),
            vec!["v=spf1 ip4:203.0.113.8 include:example.com -all".to_string()]
        );
        assert_eq!(store.snapshot().get("example.com"), Some(&result.applied));
    }

    #[tokio::test]
    async fn apply_removes_the_saved_ipv4_family_when_only_ipv6_is_discovered() {
        let dns =
            FakeDns::new(&["v=spf1 ip4:203.0.113.7 ip6:2001:db8::7 include:example.com -all"]);
        let store = MemorySpfAddressStore::with_initial([(
            "example.com".to_string(),
            SpfAddresses {
                ipv4: Some("203.0.113.7".parse().unwrap()),
                ipv6: Some("2001:db8::7".parse().unwrap()),
            },
        )]);
        let discovery = FakeDiscovery(DiscoveredAddresses {
            ipv4: None,
            ipv6: Some("2001:db8::8".parse().unwrap()),
        });
        let result = apply(
            &dns,
            &store,
            &discovery,
            &CountingPolicy::new(2),
            "example.com",
        )
        .await
        .unwrap();
        assert!(result.changed);
        assert_eq!(
            result.desired_record,
            "v=spf1 ip6:2001:db8::8 include:example.com -all"
        );
        assert_eq!(result.applied.ipv4, None);
        assert_eq!(result.applied.ipv6, Some("2001:db8::8".parse().unwrap()));
        assert_eq!(
            dns.records(),
            vec!["v=spf1 ip6:2001:db8::8 include:example.com -all".to_string()]
        );
        assert_eq!(store.snapshot().get("example.com"), Some(&result.applied));
    }

    #[tokio::test]
    async fn apply_refuses_when_both_families_are_unavailable_without_mutating_dns_or_storage() {
        let dns = FakeDns::new(&["v=spf1 ip4:203.0.113.7 ip6:2001:db8::7 -all"]);
        let applied = SpfAddresses {
            ipv4: Some("203.0.113.7".parse().unwrap()),
            ipv6: Some("2001:db8::7".parse().unwrap()),
        };
        let store = MemorySpfAddressStore::with_initial([("example.com".to_string(), applied)]);
        let discovery = FakeDiscovery(DiscoveredAddresses::default());

        let snapshot = inspect(
            &dns,
            &discovery,
            &store,
            &CountingPolicy::new(1),
            &request(),
        )
        .await;
        assert!(snapshot.desired.is_empty());
        assert!(!snapshot.needs_update);
        assert_eq!(snapshot.applied, applied);
        assert!(snapshot.error.is_none());

        let error = apply(
            &dns,
            &store,
            &discovery,
            &CountingPolicy::new(1),
            "example.com",
        )
        .await
        .unwrap_err();
        assert!(matches!(error, SpfError::NoDiscoveredAddress));
        // `inspect` above performed one read; `apply` must not perform either
        // another read or a write before refusing.
        assert_eq!(dns.list_count(), 1);
        assert_eq!(dns.write_count(), 0);
        assert_eq!(store.snapshot().get("example.com"), Some(&applied));
    }

    #[tokio::test]
    async fn inspect_requires_an_update_when_a_stale_managed_address_remains() {
        let dns = FakeDns::new(&["v=spf1 ip4:8.8.8.7 ip4:9.9.9.9 -all"]);
        let store = MemorySpfAddressStore::with_initial([(
            "example.com".to_string(),
            SpfAddresses {
                ipv4: Some("8.8.8.7".parse().unwrap()),
                ipv6: None,
            },
        )]);
        let discovery = FakeDiscovery(DiscoveredAddresses {
            ipv4: Some("9.9.9.9".parse().unwrap()),
            ipv6: None,
        });
        let snapshot = inspect(
            &dns,
            &discovery,
            &store,
            &CountingPolicy::new(1),
            &request(),
        )
        .await;
        assert!(snapshot.matches);
        assert!(snapshot.needs_update);
        assert_eq!(
            snapshot.current.as_deref(),
            Some("v=spf1 ip4:8.8.8.7 ip4:9.9.9.9 -all")
        );
        assert_eq!(snapshot.desired, "v=spf1 ip4:9.9.9.9 -all");
    }

    #[tokio::test]
    async fn apply_removes_a_stale_managed_address_that_still_matches_coverage() {
        let dns = FakeDns::new(&["v=spf1 ip4:8.8.8.7 ip4:9.9.9.9 -all"]);
        let store = MemorySpfAddressStore::with_initial([(
            "example.com".to_string(),
            SpfAddresses {
                ipv4: Some("8.8.8.7".parse().unwrap()),
                ipv6: None,
            },
        )]);
        let discovery = FakeDiscovery(DiscoveredAddresses {
            ipv4: Some("9.9.9.9".parse().unwrap()),
            ipv6: None,
        });
        let result = apply(
            &dns,
            &store,
            &discovery,
            &CountingPolicy::new(2),
            "example.com",
        )
        .await
        .unwrap();
        assert!(result.changed);
        assert_eq!(result.desired_record, "v=spf1 ip4:9.9.9.9 -all");
        assert_eq!(dns.records(), vec!["v=spf1 ip4:9.9.9.9 -all".to_string()]);
        assert_eq!(result.applied.ipv4, Some("9.9.9.9".parse().unwrap()));
    }

    #[tokio::test]
    async fn inspect_trims_the_domain_like_apply() {
        let dns = FakeDns::new(&["v=spf1 -all"]);
        let snapshot = inspect(
            &dns,
            &public_discovery(),
            &MemorySpfAddressStore::new(),
            &CountingPolicy::new(1),
            &InspectRequest::new("  example.com  ", "Test provider"),
        )
        .await;
        assert_eq!(snapshot.domain, "example.com");
        assert_eq!(dns.queried_names(), vec!["example.com".to_string()]);
        assert!(snapshot.needs_update);
    }

    #[tokio::test]
    async fn apply_writes_preserving_unrelated_txt_and_saves_addresses() {
        let dns = FakeDns::new(&["verification=keep", "v=spf1 include:example.com -all"]);
        let store = MemorySpfAddressStore::new();
        let policy = CountingPolicy::new(2);
        let result = apply(&dns, &store, &public_discovery(), &policy, "example.com")
            .await
            .unwrap();
        assert!(result.changed);
        assert_eq!(
            result.desired_record,
            "v=spf1 ip4:203.0.113.8 ip6:2001:db8::8 include:example.com -all"
        );
        assert_eq!(
            dns.records(),
            vec![
                "verification=keep".to_string(),
                "v=spf1 ip4:203.0.113.8 ip6:2001:db8::8 include:example.com -all".to_string()
            ]
        );
        assert_eq!(store.snapshot().get("example.com"), Some(&result.applied));
        assert_eq!(dns.list_count(), 2);
        assert_eq!(dns.write_count(), 1);
        assert_eq!(policy.checks(), 2);
    }

    #[tokio::test]
    async fn apply_removes_a_private_family_and_clears_its_saved_address() {
        let dns = FakeDns::new(&["v=spf1 ip4:8.8.8.7 -all"]);
        let store = MemorySpfAddressStore::with_initial([(
            "example.com".to_string(),
            SpfAddresses {
                ipv4: Some("8.8.8.7".parse().unwrap()),
                ipv6: None,
            },
        )]);
        let discovery = FakeDiscovery(DiscoveredAddresses {
            ipv4: Some("192.168.1.2".parse().unwrap()),
            ipv6: Some("2001:db8::8".parse().unwrap()),
        });
        let result = apply(
            &dns,
            &store,
            &discovery,
            &CountingPolicy::new(2),
            "example.com",
        )
        .await
        .unwrap();
        assert_eq!(result.desired_record, "v=spf1 ip6:2001:db8::8 -all");
        assert_eq!(result.applied.ipv4, None);
        assert_eq!(result.applied.ipv6, Some("2001:db8::8".parse().unwrap()));
        assert!(
            !dns.records()
                .iter()
                .any(|record| record.contains("192.168.1.2"))
        );
        assert!(
            !dns.records()
                .iter()
                .any(|record| record.contains("8.8.8.7"))
        );
        assert_eq!(store.snapshot().get("example.com"), Some(&result.applied));
    }

    #[tokio::test]
    async fn apply_refuses_discovery_of_only_non_public_addresses() {
        let dns = FakeDns::new(&["v=spf1 ip4:8.8.8.7 -all"]);
        let store = MemorySpfAddressStore::new();
        let discovery = FakeDiscovery(DiscoveredAddresses {
            ipv4: Some("192.168.1.2".parse().unwrap()),
            ipv6: Some("fd00::1".parse().unwrap()),
        });
        let error = apply(
            &dns,
            &store,
            &discovery,
            &CountingPolicy::new(1),
            "example.com",
        )
        .await
        .unwrap_err();
        assert!(matches!(error, SpfError::NoDiscoveredAddress));
        assert_eq!(dns.list_count(), 0);
        assert_eq!(dns.write_count(), 0);
        assert!(store.snapshot().is_empty());
    }

    #[tokio::test]
    async fn apply_is_idempotent_when_the_record_already_matches() {
        let dns = FakeDns::new(&["v=spf1 ip4:8.8.8.7 -all"]);
        let discovery = FakeDiscovery(DiscoveredAddresses {
            ipv4: Some("8.8.8.7".parse().unwrap()),
            ipv6: None,
        });
        let store = MemorySpfAddressStore::new();
        let result = apply(
            &dns,
            &store,
            &discovery,
            &CountingPolicy::new(1),
            "example.com",
        )
        .await
        .unwrap();
        assert!(!result.changed);
        assert_eq!(dns.write_count(), 0);
        assert_eq!(dns.list_count(), 2);
        assert!(result.message.contains("already has"));
    }

    #[tokio::test]
    async fn apply_refuses_a_disabled_provider_without_touching_dns() {
        let dns = FakeDns::new(&["v=spf1 -all"]);
        let error = apply(
            &dns,
            &MemorySpfAddressStore::new(),
            &public_discovery(),
            &CountingPolicy::new(0),
            "example.com",
        )
        .await
        .unwrap_err();
        assert!(matches!(error, SpfError::WriteUnavailable(_)));
        assert_eq!(dns.list_count(), 0);
        assert_eq!(dns.write_count(), 0);
    }

    #[tokio::test]
    async fn apply_refuses_disabled_spf_even_when_the_provider_is_enabled() {
        let dns = FakeDns::new(&["v=spf1 -all"]);
        let policy = FixedWritePolicy::new(Availability::spf_disabled("SPF is disabled."));
        let error = apply(
            &dns,
            &MemorySpfAddressStore::new(),
            &public_discovery(),
            &policy,
            "example.com",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, SpfError::WriteUnavailable(reason) if reason == "SPF is disabled.")
        );
        assert_eq!(dns.list_count(), 0);
        assert_eq!(dns.write_count(), 0);
    }

    #[tokio::test]
    async fn apply_refuses_a_disabled_provider_even_when_spf_is_enabled() {
        let dns = FakeDns::new(&["v=spf1 -all"]);
        let policy = FixedWritePolicy::new(Availability::provider_disabled(
            true,
            "Provider is disabled.",
        ));
        let error = apply(
            &dns,
            &MemorySpfAddressStore::new(),
            &public_discovery(),
            &policy,
            "example.com",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, SpfError::WriteUnavailable(reason) if reason == "Provider is disabled.")
        );
        assert_eq!(dns.list_count(), 0);
        assert_eq!(dns.write_count(), 0);
    }

    #[tokio::test]
    async fn apply_refuses_a_host_write_policy_without_touching_dns() {
        let dns = FakeDns::new(&["v=spf1 -all"]);
        let policy = FixedWritePolicy::new(Availability {
            spf_enabled: true,
            provider_enabled: true,
            write_available: false,
            reason: Some("Maintenance mode.".into()),
        });
        let error = apply(
            &dns,
            &MemorySpfAddressStore::new(),
            &public_discovery(),
            &policy,
            "example.com",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, SpfError::WriteUnavailable(reason) if reason == "Maintenance mode.")
        );
        assert_eq!(dns.list_count(), 0);
        assert_eq!(dns.write_count(), 0);
    }

    #[tokio::test]
    async fn a_successful_write_rechecks_both_spf_and_provider_settings() {
        let dns = FakeDns::new(&["v=spf1 include:example.com -all"]);
        let store = MemorySpfAddressStore::new();
        let policy = FixedWritePolicy::new(Availability {
            spf_enabled: true,
            provider_enabled: true,
            write_available: true,
            reason: None,
        });
        let result = apply(&dns, &store, &public_discovery(), &policy, "example.com")
            .await
            .unwrap();
        assert!(result.changed);
        assert_eq!(dns.write_count(), 1);
    }

    #[tokio::test]
    async fn ensure_write_allowed_falls_back_to_the_disabled_setting() {
        let spf_disabled = Availability {
            spf_enabled: false,
            provider_enabled: true,
            write_available: true,
            reason: None,
        };
        let error = ensure_write_allowed(spf_disabled).unwrap_err();
        assert!(
            matches!(error, SpfError::WriteUnavailable(reason) if reason.contains("Enable SPF"))
        );

        let policy_disabled = Availability {
            spf_enabled: true,
            provider_enabled: true,
            write_available: false,
            reason: None,
        };
        let error = ensure_write_allowed(policy_disabled).unwrap_err();
        assert!(
            matches!(error, SpfError::WriteUnavailable(reason) if reason.contains("write policy"))
        );
    }

    #[tokio::test]
    async fn apply_rechecks_the_settings_seam_before_writing() {
        let dns = FakeDns::new(&["v=spf1 include:example.com -all"]);
        let store = MemorySpfAddressStore::new();
        let policy = CountingPolicy::new(1);
        let error = apply(&dns, &store, &public_discovery(), &policy, "example.com")
            .await
            .unwrap_err();
        assert!(matches!(error, SpfError::WriteUnavailable(_)));
        assert_eq!(policy.checks(), 2);
        assert_eq!(dns.list_count(), 1);
        assert_eq!(dns.write_count(), 0);
        assert!(store.snapshot().is_empty());
    }

    #[tokio::test]
    async fn apply_does_not_save_when_verification_fails() {
        let dns = FakeDns::with_behavior(
            &["v=spf1 include:example.com -all"],
            ReplaceBehavior::StoreWrong,
        );
        let store = MemorySpfAddressStore::new();
        let error = apply(
            &dns,
            &store,
            &public_discovery(),
            &CountingPolicy::new(2),
            "example.com",
        )
        .await
        .unwrap_err();
        assert!(matches!(error, SpfError::Verification));
        assert_eq!(dns.write_count(), 1);
        assert!(store.snapshot().is_empty());
    }

    #[tokio::test]
    async fn apply_reports_dns_change_when_saving_addresses_fails() {
        let dns = FakeDns::new(&["v=spf1 include:example.com -all"]);
        let error = apply(
            &dns,
            &FailingStore,
            &public_discovery(),
            &CountingPolicy::new(2),
            "example.com",
        )
        .await
        .unwrap_err();
        assert!(matches!(error, SpfError::SaveApplied(_)));
        assert!(dns.records().iter().any(|record| is_spf(record)));
        assert_eq!(dns.write_count(), 1);
    }

    #[tokio::test]
    async fn apply_refuses_multiple_records_and_missing_addresses() {
        let multiple = FakeDns::new(&["v=spf1 -all", "v=spf1 ~all"]);
        let error = apply(
            &multiple,
            &MemorySpfAddressStore::new(),
            &public_discovery(),
            &CountingPolicy::new(2),
            "example.com",
        )
        .await
        .unwrap_err();
        assert!(matches!(error, SpfError::MultipleSpfRecords));
        assert_eq!(multiple.write_count(), 0);

        let dns = FakeDns::new(&["v=spf1 -all"]);
        let error = apply(
            &dns,
            &MemorySpfAddressStore::new(),
            &FakeDiscovery(DiscoveredAddresses::default()),
            &CountingPolicy::new(1),
            "example.com",
        )
        .await
        .unwrap_err();
        assert!(matches!(error, SpfError::NoDiscoveredAddress));
        assert_eq!(dns.list_count(), 0);
    }

    #[tokio::test]
    async fn apply_requires_a_domain() {
        let dns = FakeDns::new(&[]);
        let error = apply(
            &dns,
            &MemorySpfAddressStore::new(),
            &public_discovery(),
            &CountingPolicy::new(1),
            "   ",
        )
        .await
        .unwrap_err();
        assert!(matches!(error, SpfError::NoDomain));
        assert_eq!(dns.list_count(), 0);
    }
}
