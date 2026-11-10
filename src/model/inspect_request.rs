//! The domain and source label used for an inspection.

/// The domain and source label used for an inspection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectRequest {
    /// The canonical, validated domain to inspect. Authorization is host-owned.
    pub domain: super::DomainName,
    /// For example, the DNS provider's name, or `authoritative DNS`.
    pub source: String,
}

impl InspectRequest {
    pub fn new(domain: super::DomainName, source: impl Into<String>) -> Self {
        Self {
            domain,
            source: source.into(),
        }
    }
}
