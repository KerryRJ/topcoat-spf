//! The planned TXT RRset and desired SPF value.

/// The planned TXT RRset and the desired SPF value inside it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rewrite {
    /// All TXT values to publish, preserving unrelated records and appending
    /// the desired SPF record last.
    pub records: Vec<String>,
    /// The desired SPF record.
    pub desired: crate::SpfRecordText,
}
