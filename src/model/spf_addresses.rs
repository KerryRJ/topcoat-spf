//! Addresses last successfully published for a domain.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::DiscoveredAddresses;

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
