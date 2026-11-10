//! Reusable SPF inspection, rewriting and optional Topcoat UI.
//!
//! The core crate is host-independent:
//!
//! * [`SpfDns`] exposes only TXT reads and full-RRset replacement.
//! * [`SpfAddressStore`] persists the IPv4/IPv6 addresses this feature last
//!   successfully published. It stores the latest confirmed values, not
//!   discovered addresses or a history.
//! * [`WritePolicy`] is a settings-backed seam that the service re-reads before
//!   writing and returns the independent SPF enabled, provider enabled and
//!   host write-policy states. [`FixedWritePolicy`] is the explicit guarded
//!   alternative.
//! * [`PublicAddressDiscovery`] supplies public IPv4/IPv6 addresses.
//! * [`inspect`] and [`apply`] coordinate the asynchronous operations.
//!
//! Rewriting is deliberately conservative: it replaces only exact `pass`
//! `ip4`/`ip6` host directives matching the previously applied addresses and
//! removes the directive for a family that discovery did not provide. It
//! preserves unrelated TXT values and leaves other SPF mechanisms and modifiers
//! alone. The optional `ui` feature renders a Topcoat panel. The crate bundles
//! no DNS provider or public-address discovery adapter: hosts implement
//! [`SpfDns`] and [`PublicAddressDiscovery`] in their own crates and inject them
//! into [`inspect`] and [`apply`].
//!
//! Applications own authentication, authorization, CSRF protection, secure
//! credential storage, per-domain serialization and choice of provider. See
//! `README.md` for integration and atomicity limits.
//!
//! ```text
//! let domain = DomainName::new("example.com")?;
//! let snapshot = inspect(&dns, &discovery, &store, &policy, &request).await;
//! let result = apply(&dns, &store, &discovery, &policy, &domain).await?;
//! ```
//!
//! The public traits return `Send` futures so the service is usable from
//! multithreaded async servers. Implementations can use `async fn`.

mod error;
mod model;
mod service;
mod spf;

pub use error::SpfError;
pub use model::{
    ApplyResult, Availability, DiscoveredAddresses, DomainName, DomainNameError, InspectRequest,
    Snapshot, SpfAddresses, SpfRecordText, UsablePublicAddresses,
};
pub use service::{
    FixedWritePolicy, MemorySpfAddressStore, PublicAddressDiscovery, SpfAddressStore, SpfDns,
    WritePolicy, apply, inspect,
};
pub use spf::{
    Rewrite, desired_spf_record, desired_spf_record_checked, is_public_ipv4, is_public_ipv6,
    is_spf, record_includes_ip, record_matches_public_addresses, records_equivalent,
    replace_txt_records, replace_txt_records_checked,
};

#[cfg(feature = "ui")]
pub mod components;
#[cfg(feature = "preview")]
pub mod preview;
#[cfg(feature = "ui")]
pub mod ui;
