//! The result of a successful, verified SPF update.

use super::SpfAddresses;

/// The result of a successful, verified SPF update.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyResult {
    /// The SPF record that was written or confirmed.
    pub desired_record: crate::SpfRecordText,
    /// Whether the TXT RRset changed.
    pub changed: bool,
    /// Addresses to retain as the latest successfully published values for the
    /// next update.
    pub applied: SpfAddresses,
    /// A host-presentable success message.
    pub message: String,
}
