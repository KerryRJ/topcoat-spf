//! Read-only view of the current and desired SPF state.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::{Availability, SpfAddresses};

/// A read-only view of the current and desired SPF state for a host page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// The canonical DNS name whose TXT RRset was inspected.
    pub domain: super::DomainName,
    /// Host-supplied label for where the current record was read from.
    pub source: String,
    /// The first SPF TXT value found, if any.
    pub current: Option<String>,
    /// The validated record Apply would publish, or `None` when no safe
    /// proposal can be computed.
    pub desired: Option<super::SpfRecordText>,
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
