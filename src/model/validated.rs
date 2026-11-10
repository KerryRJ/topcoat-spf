//! Validated values at domain, proposal and rewrite boundaries.
use crate::{DiscoveredAddresses, SpfError, is_public_ipv4, is_public_ipv6};
use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

/// An ASCII DNS hostname, lowercase and without a final root dot.
/// Unicode names must be converted to IDNA A-labels by the host first.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct DomainName(String);

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Invalid domain name: {0}")]
pub struct DomainNameError(pub &'static str);

impl DomainName {
    pub fn new(value: impl AsRef<str>) -> Result<Self, DomainNameError> {
        let value = value.as_ref().trim();
        let value = value.strip_suffix('.').unwrap_or(value);
        if value.is_empty() {
            return Err(DomainNameError("a hostname is required"));
        }
        if !value.is_ascii() {
            return Err(DomainNameError("use ASCII IDNA A-labels, not Unicode"));
        }
        if value.len() > 253 {
            return Err(DomainNameError("hostname exceeds 253 bytes"));
        }
        for label in value.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(DomainNameError("labels must contain 1 to 63 bytes"));
            }
            if label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Err(DomainNameError(
                    "labels require letters, digits or interior hyphens",
                ));
            }
        }
        Ok(Self(value.to_ascii_lowercase()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn into_string(self) -> String {
        self.0
    }
}

/// A syntactically parsed SPF proposal. Original spelling is retained.
/// This is not proof of authorization or successful SPF evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpfRecordText(String);
impl SpfRecordText {
    pub fn new(value: impl Into<String>) -> Result<Self, SpfError> {
        let value = value.into();
        crate::spf::parse_record(&value)?;
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn into_string(self) -> String {
        self.0
    }
}

macro_rules! text_access {
    ($ty:ty, $err:ty) => {
        impl AsRef<str> for $ty {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }
        impl std::ops::Deref for $ty {
            type Target = str;
            fn deref(&self) -> &str {
                self.as_str()
            }
        }
        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
        impl FromStr for $ty {
            type Err = $err;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::new(s)
            }
        }
        impl TryFrom<String> for $ty {
            type Error = $err;
            fn try_from(s: String) -> Result<Self, Self::Error> {
                Self::new(s)
            }
        }
        impl TryFrom<&str> for $ty {
            type Error = $err;
            fn try_from(s: &str) -> Result<Self, Self::Error> {
                Self::new(s)
            }
        }
        impl From<$ty> for String {
            fn from(s: $ty) -> Self {
                s.into_string()
            }
        }
    };
}
text_access!(DomainName, DomainNameError);
text_access!(SpfRecordText, SpfError);
impl PartialEq<&str> for SpfRecordText {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

/// At least one usable address, checked with the crate's existing IP policy.
/// Unlike discovery filtering, construction rejects any supplied unusable family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UsablePublicAddresses {
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
}
impl UsablePublicAddresses {
    pub fn new(ipv4: Option<Ipv4Addr>, ipv6: Option<Ipv6Addr>) -> Result<Self, SpfError> {
        if ipv4.is_none() && ipv6.is_none() {
            return Err(SpfError::NoPublicAddress);
        }
        if ipv4.is_some_and(|ip| !is_public_ipv4(ip)) || ipv6.is_some_and(|ip| !is_public_ipv6(ip))
        {
            return Err(SpfError::InvalidPublicAddress);
        }
        Ok(Self { ipv4, ipv6 })
    }
    pub fn ipv4(self) -> Option<Ipv4Addr> {
        self.ipv4
    }
    pub fn ipv6(self) -> Option<Ipv6Addr> {
        self.ipv6
    }
}
impl TryFrom<DiscoveredAddresses> for UsablePublicAddresses {
    type Error = SpfError;
    fn try_from(value: DiscoveredAddresses) -> Result<Self, Self::Error> {
        Self::new(value.ipv4, value.ipv6)
    }
}
