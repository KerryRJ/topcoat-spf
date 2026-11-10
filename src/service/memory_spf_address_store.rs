//! A reusable in-memory applied-address store.

use std::{collections::HashMap, convert::Infallible, sync::Mutex};

use crate::SpfAddresses;

use super::SpfAddressStore;

/// A reusable in-memory last-published-address store for examples, previews
/// and tests.
///
/// Values are process-local and are discarded when the store is dropped.
#[derive(Default)]
pub struct MemorySpfAddressStore {
    values: Mutex<HashMap<crate::DomainName, SpfAddresses>>,
}

impl MemorySpfAddressStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_initial(
        values: impl IntoIterator<Item = (crate::DomainName, SpfAddresses)>,
    ) -> Self {
        Self {
            values: Mutex::new(values.into_iter().collect()),
        }
    }

    pub fn snapshot(&self) -> HashMap<crate::DomainName, SpfAddresses> {
        self.values
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }
}

impl SpfAddressStore for MemorySpfAddressStore {
    type Error = Infallible;

    async fn load(&self, domain: &crate::DomainName) -> Result<SpfAddresses, Self::Error> {
        Ok(self
            .values
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(domain)
            .copied()
            .unwrap_or_default())
    }

    async fn save(
        &self,
        domain: &crate::DomainName,
        addresses: &SpfAddresses,
    ) -> Result<(), Self::Error> {
        self.values
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(domain.to_owned(), *addresses);
        Ok(())
    }
}
