//! Errors returned by SPF inspection and updates.

/// A failed SPF inspection, rewrite, DNS write, verification or storage step.
///
/// Variants carry only backend text that the host has chosen to expose. Hosts
/// must ensure their [`SpfDns`](crate::SpfDns),
/// [`SpfAddressStore`](crate::SpfAddressStore) and
/// [`WritePolicy`](crate::WritePolicy) error `Display` implementations never
/// include credentials.
#[derive(Debug, thiserror::Error)]
pub enum SpfError {
    #[error("A supplied address is excluded by the public IP policy.")]
    InvalidPublicAddress,
    /// The existing or proposed SPF record could not be parsed or mapped.
    #[error("{0}")]
    InvalidRecord(String),
    /// More than one SPF TXT record exists at the name.
    #[error("Multiple SPF TXT records exist. Resolve them before updating.")]
    MultipleSpfRecords,
    /// No usable public address was supplied for the desired record.
    #[error("A valid SPF record requires at least one public IPv4 or IPv6 address.")]
    NoPublicAddress,
    /// Address discovery returned neither a public IPv4 nor a public IPv6 address.
    #[error("No public IP address could be discovered. DNS was not changed.")]
    NoDiscoveredAddress,
    /// No domain was supplied for an update.
    #[error("Set a domain before updating SPF.")]
    NoDomain,
    /// The host's settings-backed policy does not currently allow DNS writes.
    /// This covers SPF disabled, provider disabled or a host write restriction.
    #[error("SPF updates are unavailable: {0}")]
    WriteUnavailable(String),
    /// The host's SPF or provider write policy could not be read.
    #[error("SPF and provider settings could not be read: {0}")]
    Policy(String),
    /// TXT records could not be read from the DNS provider.
    #[error("DNS TXT lookup failed: {0}")]
    Lookup(String),
    /// A DNS write failed or its outcome is unknown.
    #[error("SPF update failed; DNS may be partially changed. Refresh before retrying: {0}")]
    Write(String),
    /// The provider's read-back did not match the expected TXT set.
    #[error(
        "The DNS provider did not return the expected TXT records after the update. Success could not be verified; stored addresses were not changed."
    )]
    Verification,
    /// The read-back after a successful write could not be performed.
    #[error(
        "DNS provider verification lookup failed after the update; stored addresses were not changed: {0}"
    )]
    VerificationLookup(String),
    /// DNS changed, but the host's applied-address store rejected the save.
    #[error(
        "DNS was updated, but the applied addresses could not be saved. Restore storage access and retry before the public IP changes: {0}"
    )]
    SaveApplied(String),
    /// Previously applied addresses could not be loaded.
    #[error("Applied addresses could not be loaded: {0}")]
    LoadApplied(String),
    /// Public address discovery failed before any write.
    #[error("Public address discovery failed: {0}")]
    Discovery(String),
}
