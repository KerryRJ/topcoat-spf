//! Exercises the public API from outside the crate.

use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};
use topcoat_spf::{
    Availability, DiscoveredAddresses, FixedWritePolicy, InspectRequest, MemorySpfAddressStore,
    PublicAddressDiscovery, SpfAddresses, SpfDns, SpfError, apply, inspect,
};

struct Dns {
    records: Mutex<Vec<String>>,
    writes: AtomicUsize,
}

impl Dns {
    fn new(records: &[&str]) -> Self {
        Self {
            records: Mutex::new(records.iter().map(|record| (*record).to_owned()).collect()),
            writes: AtomicUsize::new(0),
        }
    }

    fn records(&self) -> Vec<String> {
        self.records
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }
}

impl SpfDns for Dns {
    type Error = String;

    async fn txt_records(&self, _name: &str) -> Result<Vec<String>, Self::Error> {
        Ok(self.records())
    }

    async fn replace_txt_records(
        &self,
        _name: &str,
        records: &[String],
    ) -> Result<(), Self::Error> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        *self
            .records
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = records.to_vec();
        Ok(())
    }
}

struct Discovery(DiscoveredAddresses);

impl PublicAddressDiscovery for Discovery {
    type Error = String;

    async fn discover(&self) -> Result<DiscoveredAddresses, Self::Error> {
        Ok(self.0)
    }
}

fn assert_send<T: Send>(value: T) -> T {
    value
}

#[tokio::test]
async fn public_traits_inspect_and_apply() {
    let dns = Dns::new(&["verification=keep", "v=spf1 include:example.com -all"]);
    let discovery = Discovery(DiscoveredAddresses {
        ipv4: Some("203.0.113.8".parse().unwrap()),
        ipv6: None,
    });
    let store = MemorySpfAddressStore::new();
    let policy = FixedWritePolicy::available();

    let snapshot = assert_send(inspect(
        &dns,
        &discovery,
        &store,
        &policy,
        &InspectRequest::new("example.com", "Test provider"),
    ))
    .await;
    assert_eq!(
        snapshot.current.as_deref(),
        Some("v=spf1 include:example.com -all")
    );
    assert_eq!(
        snapshot.desired,
        "v=spf1 ip4:203.0.113.8 include:example.com -all"
    );
    assert!(!snapshot.matches);
    assert!(snapshot.needs_update);
    assert!(snapshot.availability.can_write());

    let result = assert_send(apply(&dns, &store, &discovery, &policy, "example.com"))
        .await
        .unwrap();
    assert!(result.changed);
    assert_eq!(
        dns.records(),
        vec![
            "verification=keep".to_string(),
            "v=spf1 ip4:203.0.113.8 include:example.com -all".to_string()
        ]
    );
    assert_eq!(dns.writes.load(Ordering::SeqCst), 1);
    assert_eq!(store.snapshot().get("example.com"), Some(&result.applied));
}

#[tokio::test]
async fn partial_discovery_removes_the_previous_family_and_clears_storage() {
    let dns = Dns::new(&[
        "verification=keep",
        "v=spf1 ip4:203.0.113.8 ip6:2001:db8::8 include:example.com -all",
    ]);
    let applied = SpfAddresses {
        ipv4: Some("203.0.113.8".parse().unwrap()),
        ipv6: Some("2001:db8::8".parse().unwrap()),
    };
    let store = MemorySpfAddressStore::with_initial([("example.com".to_string(), applied)]);
    let discovery = Discovery(DiscoveredAddresses {
        ipv4: Some("203.0.113.9".parse().unwrap()),
        ipv6: None,
    });
    let policy = FixedWritePolicy::available();

    let snapshot = inspect(
        &dns,
        &discovery,
        &store,
        &policy,
        &InspectRequest::new("example.com", "Test provider"),
    )
    .await;
    assert_eq!(
        snapshot.desired,
        "v=spf1 ip4:203.0.113.9 include:example.com -all"
    );
    assert!(snapshot.needs_update);

    let result = apply(&dns, &store, &discovery, &policy, "example.com")
        .await
        .unwrap();
    assert_eq!(result.desired_record, snapshot.desired);
    assert_eq!(
        dns.records(),
        vec![
            "verification=keep".to_string(),
            "v=spf1 ip4:203.0.113.9 include:example.com -all".to_string()
        ]
    );
    assert_eq!(
        store.snapshot().get("example.com"),
        Some(&SpfAddresses {
            ipv4: Some("203.0.113.9".parse().unwrap()),
            ipv6: None,
        })
    );
}

#[tokio::test]
async fn disabled_policy_blocks_writes() {
    let dns = Dns::new(&["v=spf1 -all"]);
    let discovery = Discovery(DiscoveredAddresses {
        ipv4: Some("203.0.113.8".parse().unwrap()),
        ipv6: None,
    });
    let store = MemorySpfAddressStore::new();
    let policy = FixedWritePolicy::disabled("Provider disabled.");
    let error = apply(&dns, &store, &discovery, &policy, "example.com")
        .await
        .unwrap_err();
    assert!(matches!(error, SpfError::WriteUnavailable(_)));
    assert_eq!(dns.writes.load(Ordering::SeqCst), 0);
    assert!(store.snapshot().is_empty());
}

#[tokio::test]
async fn service_gates_spf_and_provider_settings_independently() {
    let dns = Dns::new(&["v=spf1 -all"]);
    let discovery = Discovery(DiscoveredAddresses {
        ipv4: Some("203.0.113.8".parse().unwrap()),
        ipv6: None,
    });
    let store = MemorySpfAddressStore::new();

    let spf_off = FixedWritePolicy::new(Availability::spf_disabled("SPF is disabled."));
    let snapshot = inspect(
        &dns,
        &discovery,
        &store,
        &spf_off,
        &InspectRequest::new("example.com", "Test provider"),
    )
    .await;
    assert!(!snapshot.availability.spf_enabled);
    assert!(snapshot.availability.provider_enabled);
    assert!(!snapshot.availability.can_refresh());
    assert!(!snapshot.availability.can_write());
    let error = apply(&dns, &store, &discovery, &spf_off, "example.com")
        .await
        .unwrap_err();
    assert!(matches!(error, SpfError::WriteUnavailable(_)));
    assert_eq!(dns.writes.load(Ordering::SeqCst), 0);

    let provider_off = FixedWritePolicy::new(Availability::provider_disabled(
        true,
        "Provider is disabled.",
    ));
    let snapshot = inspect(
        &dns,
        &discovery,
        &store,
        &provider_off,
        &InspectRequest::new("example.com", "Test provider"),
    )
    .await;
    assert!(snapshot.availability.spf_enabled);
    assert!(!snapshot.availability.provider_enabled);
    assert!(!snapshot.availability.can_refresh());
    assert!(!snapshot.availability.can_write());
    let error = apply(&dns, &store, &discovery, &provider_off, "example.com")
        .await
        .unwrap_err();
    assert!(matches!(error, SpfError::WriteUnavailable(_)));
    assert_eq!(dns.writes.load(Ordering::SeqCst), 0);
    assert!(store.snapshot().is_empty());
}
