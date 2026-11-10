//! Public addresses discovered for the current host.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Public addresses discovered for the current host.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DiscoveredAddresses {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}
