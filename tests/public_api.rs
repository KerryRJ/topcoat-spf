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

    async fn txt_records(
        &self,
        _name: &topcoat_spf::DomainName,
    ) -> Result<Vec<String>, Self::Error> {
        Ok(self.records())
    }

    async fn replace_txt_records(
        &self,
        _name: &topcoat_spf::DomainName,
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
        &InspectRequest::new(
            topcoat_spf::DomainName::new(&topcoat_spf::DomainName::new("example.com").unwrap())
                .unwrap(),
            "Test provider",
        ),
    ))
    .await;
    assert_eq!(
        snapshot.current.as_deref(),
        Some("v=spf1 include:example.com -all")
    );
    assert_eq!(
        snapshot.desired.as_deref(),
        Some("v=spf1 ip4:203.0.113.8 include:example.com -all")
    );
    assert!(!snapshot.matches);
    assert!(snapshot.needs_update);
    assert!(snapshot.availability.can_write());

    let result = assert_send(apply(
        &dns,
        &store,
        &discovery,
        &policy,
        &topcoat_spf::DomainName::new("example.com").unwrap(),
    ))
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
    assert_eq!(
        store
            .snapshot()
            .get(&topcoat_spf::DomainName::new("example.com").unwrap()),
        Some(&result.applied)
    );
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
    let store = MemorySpfAddressStore::with_initial([(
        topcoat_spf::DomainName::new("example.com").unwrap(),
        applied,
    )]);
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
        &InspectRequest::new(
            topcoat_spf::DomainName::new("example.com").unwrap(),
            "Test provider",
        ),
    )
    .await;
    assert_eq!(
        snapshot.desired.as_deref(),
        Some("v=spf1 ip4:203.0.113.9 include:example.com -all")
    );
    assert!(snapshot.needs_update);

    let result = apply(
        &dns,
        &store,
        &discovery,
        &policy,
        &topcoat_spf::DomainName::new("example.com").unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(Some(result.desired_record), snapshot.desired);
    assert_eq!(
        dns.records(),
        vec![
            "verification=keep".to_string(),
            "v=spf1 ip4:203.0.113.9 include:example.com -all".to_string()
        ]
    );
    assert_eq!(
        store
            .snapshot()
            .get(&topcoat_spf::DomainName::new("example.com").unwrap()),
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
    let error = apply(
        &dns,
        &store,
        &discovery,
        &policy,
        &topcoat_spf::DomainName::new("example.com").unwrap(),
    )
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
        &InspectRequest::new(
            topcoat_spf::DomainName::new("example.com").unwrap(),
            "Test provider",
        ),
    )
    .await;
    assert!(!snapshot.availability.spf_enabled);
    assert!(snapshot.availability.provider_enabled);
    assert!(!snapshot.availability.can_refresh());
    assert!(!snapshot.availability.can_write());
    let error = apply(
        &dns,
        &store,
        &discovery,
        &spf_off,
        &topcoat_spf::DomainName::new("example.com").unwrap(),
    )
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
        &InspectRequest::new(
            topcoat_spf::DomainName::new("example.com").unwrap(),
            "Test provider",
        ),
    )
    .await;
    assert!(snapshot.availability.spf_enabled);
    assert!(!snapshot.availability.provider_enabled);
    assert!(!snapshot.availability.can_refresh());
    assert!(!snapshot.availability.can_write());
    let error = apply(
        &dns,
        &store,
        &discovery,
        &provider_off,
        &topcoat_spf::DomainName::new("example.com").unwrap(),
    )
    .await
    .unwrap_err();
    assert!(matches!(error, SpfError::WriteUnavailable(_)));
    assert_eq!(dns.writes.load(Ordering::SeqCst), 0);
    assert!(store.snapshot().is_empty());
}

#[test]
fn domain_validation_and_canonicalization() {
    use topcoat_spf::DomainName;
    let canonical: DomainName = "  ExAmPlE.COM. \n".parse().unwrap();
    assert_eq!(canonical.as_str(), "example.com");
    assert_eq!(canonical, DomainName::try_from("example.com").unwrap());
    assert_eq!(
        DomainName::new("xn--bcher-kva.example").unwrap().as_str(),
        "xn--bcher-kva.example"
    );
    for invalid in [
        "",
        " ",
        ".",
        "example..com",
        "example.com..",
        "-a.com",
        "a-.com",
        "_spf.example",
        "a b.com",
        "a\nb.com",
        "https://example.com",
        "bücher.example",
    ] {
        assert!(DomainName::new(invalid).is_err(), "{invalid:?}");
    }
    assert!(DomainName::new(format!("{}.com", "a".repeat(64))).is_err());
    let longest = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    ]
    .join(".");
    assert!(DomainName::new(&longest).is_ok());
    assert!(DomainName::new(format!("{longest}x")).is_err());
}

#[tokio::test]
async fn equivalent_domain_spellings_share_one_storage_key() {
    use topcoat_spf::{DomainName, SpfAddressStore, SpfAddresses};
    let store = MemorySpfAddressStore::new();
    let initial = SpfAddresses {
        ipv4: Some("203.0.113.8".parse().unwrap()),
        ipv6: None,
    };
    store
        .save(&DomainName::new(" Example.COM. ").unwrap(), &initial)
        .await
        .unwrap();
    assert_eq!(
        store
            .load(&DomainName::new("example.com").unwrap())
            .await
            .unwrap(),
        initial
    );
    store
        .save(
            &DomainName::new("EXAMPLE.com").unwrap(),
            &SpfAddresses::default(),
        )
        .await
        .unwrap();
    assert_eq!(store.snapshot().len(), 1);
    assert_eq!(
        store.snapshot().keys().next().unwrap().as_str(),
        "example.com"
    );
}

#[test]
fn checked_rewrite_requires_nonempty_usable_addresses_and_preserves_text() {
    use topcoat_spf::{
        SpfAddresses, SpfError, SpfRecordText, UsablePublicAddresses, replace_txt_records_checked,
    };
    assert!(matches!(
        UsablePublicAddresses::new(None, None),
        Err(SpfError::NoPublicAddress)
    ));
    for ip in [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.1.1",
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
    ] {
        assert!(UsablePublicAddresses::new(Some(ip.parse().unwrap()), None).is_err());
    }
    for ip in ["::1", "::", "fc00::1", "fe80::1", "ff02::1"] {
        assert!(
            UsablePublicAddresses::new(
                Some("203.0.113.8".parse().unwrap()),
                Some(ip.parse().unwrap())
            )
            .is_err()
        );
    }
    let addresses = UsablePublicAddresses::new(
        Some("203.0.113.8".parse().unwrap()),
        Some("2001:db8::8".parse().unwrap()),
    )
    .unwrap();
    assert!(addresses.ipv4().is_some());
    assert!(addresses.ipv6().is_some());
    let raw = "v=spf1 include:Example.COM -all";
    let proposal = SpfRecordText::new(raw).unwrap();
    assert_eq!(proposal.as_str(), raw);
    for bad in ["", "verification=hello", "v=spf1 ip4:invalid -all"] {
        assert!(SpfRecordText::new(bad).is_err());
    }
    let rewrite = replace_txt_records_checked(
        &["verification= Keep Me ".into(), raw.into()],
        addresses,
        &SpfAddresses::default(),
    )
    .unwrap();
    assert_eq!(rewrite.records[0], "verification= Keep Me ");
    assert_eq!(
        rewrite.desired.as_str(),
        "v=spf1 ip4:203.0.113.8 ip6:2001:db8::8 include:Example.COM -all"
    );
    assert_eq!(rewrite.records[1], rewrite.desired.as_str());
}

#[tokio::test]
async fn unavailable_or_malformed_proposals_are_none_without_losing_raw_txt() {
    let domain = topcoat_spf::DomainName::new("Example.COM.").unwrap();
    let request = InspectRequest::new(domain, "Test provider");
    let store = MemorySpfAddressStore::new();
    let policy = FixedWritePolicy::available();
    let malformed = "v=spf1 ip4:invalid -all";
    let dns = Dns::new(&["verification=keep", malformed]);
    let discovery = Discovery(DiscoveredAddresses {
        ipv4: Some("203.0.113.8".parse().unwrap()),
        ipv6: None,
    });
    let snapshot = inspect(&dns, &discovery, &store, &policy, &request).await;
    assert_eq!(snapshot.current.as_deref(), Some(malformed));
    assert_eq!(snapshot.desired, None);
    assert!(snapshot.error.as_deref().unwrap().contains("SPF"));
    assert!(!snapshot.needs_update);
    assert_eq!(dns.records(), vec!["verification=keep", malformed]);
    let dns = Dns::new(&["v=spf1 -all"]);
    let snapshot = inspect(
        &dns,
        &Discovery(DiscoveredAddresses::default()),
        &store,
        &policy,
        &request,
    )
    .await;
    assert_eq!(snapshot.desired, None);
    assert!(!snapshot.needs_update);
    let snapshot = inspect(&dns, &discovery, &store, &policy, &request).await;
    let proposal: &topcoat_spf::SpfRecordText = snapshot.desired.as_ref().unwrap();
    assert_eq!(proposal.as_str(), "v=spf1 ip4:203.0.113.8 -all");
}

#[test]
fn strict_spf_syntax_is_shared_by_proposals_and_rewrite_inputs() {
    use topcoat_spf::{SpfRecordText, UsablePublicAddresses, desired_spf_record_checked};
    let addresses = UsablePublicAddresses::new(Some("203.0.113.8".parse().unwrap()), None).unwrap();
    let applied = SpfAddresses {
        ipv4: Some("203.0.113.7".parse().unwrap()),
        ipv6: Some("2001:db8::7".parse().unwrap()),
    };
    for term in [
        "ip4:203.0.113.7/33",
        "ip6:2001:db8::7/129",
        "ip4:203.0.113.7/",
        "ip6:2001:db8::7/",
        "ip4:203.0.113.7/-1",
        "ip6:2001:db8::7/128/1",
        "a/33",
        "mx//129",
        "a/",
        "mx//",
        "a/24/64",
        "mx/24//",
        "a:/24",
        "ip4",
        "ip6:",
        "all:example.com",
        "ptr/24",
        "include",
        "include:",
        "exists:",
        "unknown",
        "unknown:example.com",
        "+unknown",
        "-extension=value",
        "9extension=value",
        "x-extension=%",
        "x-extension=%{z}",
    ] {
        let raw = format!("v=spf1 {term} -all");
        assert!(
            matches!(SpfRecordText::new(&raw), Err(SpfError::InvalidRecord(_))),
            "proposal: {raw}"
        );
        assert!(
            matches!(
                desired_spf_record_checked(Some(&raw), addresses, &applied),
                Err(SpfError::InvalidRecord(_))
            ),
            "rewrite: {raw}"
        );
    }
    for raw in [
        "v=spf1 ip4:203.0.113.7/0 ip6:2001:db8::7/0 -all",
        "v=spf1 ip4:203.0.113.7/32 ip6:2001:db8::7/128 -all",
        "v=spf1 a/0//0 mx:example.com/32//128 -all",
        "v=spf1 a//128 mx/24 -all",
        "v=spf1 include:example.com ptr exists:example.com -all x-extension=opaque/value foo.bar_1=",
        "v=spf1 -all x-extension=%{d} redirect=example.com",
        "v=spf1 -all x-extension=%{l1r=}.example foo.bar_1=opaque%%value",
    ] {
        assert_eq!(
            SpfRecordText::new(raw)
                .unwrap_or_else(|e| panic!("{raw}: {e}"))
                .as_str(),
            raw
        );
        let rewrite = desired_spf_record_checked(Some(raw), addresses, &applied).unwrap();
        if raw.contains("x-extension=") {
            assert!(
                rewrite
                    .as_str()
                    .contains(raw.split("x-extension=").nth(1).unwrap())
            );
        }
    }
}

#[tokio::test]
async fn invalid_or_multiple_spf_records_never_propose_write_or_save() {
    use topcoat_spf::{DomainName, SpfAddressStore};
    struct Store {
        saves: AtomicUsize,
    }
    impl SpfAddressStore for Store {
        type Error = std::convert::Infallible;
        async fn load(&self, _: &DomainName) -> Result<SpfAddresses, Self::Error> {
            Ok(SpfAddresses {
                ipv4: Some("203.0.113.7".parse().unwrap()),
                ipv6: Some("2001:db8::7".parse().unwrap()),
            })
        }
        async fn save(&self, _: &DomainName, _: &SpfAddresses) -> Result<(), Self::Error> {
            self.saves.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    let domain = DomainName::new("example.com").unwrap();
    let discovery = Discovery(DiscoveredAddresses {
        ipv4: Some("203.0.113.8".parse().unwrap()),
        ipv6: None,
    });
    let policy = FixedWritePolicy::available();
    for records in [
        vec!["v=spf1 ip4:203.0.113.7/33 -all"],
        vec!["v=spf1 ip6:2001:db8::7/129 -all"],
        vec!["v=spf1 ip4:203.0.113.7/ -all"],
        vec!["v=spf1 ip6:2001:db8::7/ -all"],
        vec!["v=spf1 unknown -all"],
        vec!["v=spf1 -all", "v=spf1 ~all"],
    ] {
        let dns = Dns::new(&records);
        let store = Store {
            saves: AtomicUsize::new(0),
        };
        let snapshot = inspect(
            &dns,
            &discovery,
            &store,
            &policy,
            &InspectRequest::new(domain.clone(), "Test"),
        )
        .await;
        assert_eq!(snapshot.current.as_deref(), Some(records[0]));
        assert_eq!(snapshot.desired, None, "{records:?}");
        assert!(!snapshot.needs_update);
        assert!(snapshot.error.is_some());
        let error = apply(&dns, &store, &discovery, &policy, &domain)
            .await
            .unwrap_err();
        if records.len() > 1 {
            assert!(matches!(error, SpfError::MultipleSpfRecords));
        } else {
            assert!(matches!(error, SpfError::InvalidRecord(_)));
        }
        assert_eq!(dns.writes.load(Ordering::SeqCst), 0);
        assert_eq!(store.saves.load(Ordering::SeqCst), 0);
        assert_eq!(dns.records(), records);
    }
}
