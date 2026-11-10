//! SPF detection, address matching and conservative record rewriting.
//!
//! Rewriting preserves modifiers, unrelated TXT values and every directive this
//! feature does not own. Only exact `pass` host IP mechanisms matching the
//! previously applied addresses are replaced or removed. A family that discovery
//! did not provide is not added, so its previously managed directive is removed.

use crate::{SpfAddresses, SpfError};
use mail_auth::spf::{Mechanism, Qualifier};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

mod rewrite;
mod syntax;
pub(crate) use syntax::parse as parse_record;

pub use rewrite::Rewrite;

/// Whether a TXT value is an SPF record (`v=spf1`, case-insensitive).
pub fn is_spf(record: &str) -> bool {
    record
        .split_whitespace()
        .next()
        .is_some_and(|version| version.eq_ignore_ascii_case("v=spf1"))
}

/// Whether an SPF record contains an `ip4` or `ip6` mechanism covering
/// `address`.
///
/// This is the conservative check used by the UI status column. It ignores
/// qualifiers other than an explicit `+` prefix, matching the previous
/// application behaviour.
pub fn record_includes_ip(record: &str, address: IpAddr) -> bool {
    if !is_spf(record) {
        return false;
    }
    record.split_whitespace().skip(1).any(|term| {
        let term = term.strip_prefix('+').unwrap_or(term);
        let Some((kind, network)) = term.split_once(':') else {
            return false;
        };
        let (base, prefix) = network
            .split_once('/')
            .map(|(base, prefix)| (base, prefix.parse::<u32>().ok()))
            .unwrap_or((
                network,
                Some(if kind.eq_ignore_ascii_case("ip4") {
                    32
                } else {
                    128
                }),
            ));
        match (address, base.parse::<IpAddr>(), prefix) {
            (IpAddr::V4(ip), Ok(IpAddr::V4(base)), Some(prefix))
                if kind.eq_ignore_ascii_case("ip4") && prefix <= 32 =>
            {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                u32::from(ip) & mask == u32::from(base) & mask
            }
            (IpAddr::V6(ip), Ok(IpAddr::V6(base)), Some(prefix))
                if kind.eq_ignore_ascii_case("ip6") && prefix <= 128 =>
            {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                u128::from(ip) & mask == u128::from(base) & mask
            }
            _ => false,
        }
    })
}

/// Whether the current record includes every discovered public address.
///
/// At least one address must be present. This mirrors the previous panel:
/// a refresh that could not discover any public address does not report a
/// match, even when the stored record already contains the last applied
/// addresses.
pub fn record_matches_public_addresses(
    current: Option<&str>,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
) -> bool {
    let Some(current) = current else {
        return false;
    };
    let has_address = ipv4.is_some() || ipv6.is_some();
    has_address
        && ipv4.is_none_or(|ip| record_includes_ip(current, IpAddr::V4(ip)))
        && ipv6.is_none_or(|ip| record_includes_ip(current, IpAddr::V6(ip)))
}

/// Whether two TXT RRsets contain the same values, including duplicate counts.
pub fn records_equivalent(expected: &[String], actual: &[String]) -> bool {
    expected.len() == actual.len()
        && expected.iter().all(|record| {
            expected.iter().filter(|item| *item == record).count()
                == actual.iter().filter(|item| *item == record).count()
        })
}

/// Build the desired SPF record while preserving unrelated terms.
///
/// The previous applied addresses identify owned host directives. Newly
/// discovered public addresses are inserted before existing mechanisms. An
/// address family that is unavailable is not inserted, so its previously
/// applied host directive, if present, is removed; unrelated mechanisms,
/// networks and modifiers are preserved. At least one public address is
/// required, and with neither family available this returns
/// [`SpfError::NoPublicAddress`] without producing a rewrite. A missing record
/// is created as `v=spf1 <addresses> ~all`.
pub fn desired_spf_record(
    current_record: Option<&str>,
    public_ipv4: Option<Ipv4Addr>,
    public_ipv6: Option<Ipv6Addr>,
    applied: &SpfAddresses,
) -> Result<crate::SpfRecordText, SpfError> {
    let addresses = crate::UsablePublicAddresses::new(
        public_ipv4.filter(|ip| is_public_ipv4(*ip)),
        public_ipv6.filter(|ip| is_public_ipv6(*ip)),
    )?;
    desired_spf_record_checked(current_record, addresses, applied)
}

/// Rewrite with a validated, nonempty set of usable addresses.
pub fn desired_spf_record_checked(
    current_record: Option<&str>,
    addresses: crate::UsablePublicAddresses,
    applied: &SpfAddresses,
) -> Result<crate::SpfRecordText, SpfError> {
    let public_ipv4 = addresses.ipv4();
    let public_ipv6 = addresses.ipv6();
    let current_text = current_record.unwrap_or("v=spf1 ~all");
    let current = parse_record(current_text)?;

    // Keep the original term spelling and modifier order while using mail-auth's
    // typed parse to identify exact managed IP directives.
    let raw_terms: Vec<_> = current_text.split_ascii_whitespace().skip(1).collect();
    let directive_terms: Vec<_> = raw_terms
        .iter()
        .enumerate()
        .filter(|(_, term)| !syntax::is_modifier(term))
        .collect();
    if directive_terms.len() != current.directives.len() {
        return Err(SpfError::InvalidRecord(
            "Could not map parsed SPF directives to their original terms.".into(),
        ));
    }

    let mut retained_terms = Vec::with_capacity(raw_terms.len() + 2);
    let has_ipv4 = current
        .directives
        .iter()
        .filter(|directive| !managed_directive(directive, applied))
        .any(|directive| {
            matches!(
                (&directive.qualifier, &directive.mechanism),
                (Qualifier::Pass, Mechanism::Ip4 { addr, mask: u32::MAX })
                    if Some(*addr) == public_ipv4
            )
        });
    let has_ipv6 = current
        .directives
        .iter()
        .filter(|directive| !managed_directive(directive, applied))
        .any(|directive| {
            matches!(
                (&directive.qualifier, &directive.mechanism),
                (Qualifier::Pass, Mechanism::Ip6 { addr, mask: u128::MAX })
                    if Some(*addr) == public_ipv6
            )
        });

    // Insert new senders before existing mechanisms, including any catch-all.
    if let Some(ip) = public_ipv4.filter(|_| !has_ipv4) {
        retained_terms.push(format!("ip4:{ip}"));
    }
    if let Some(ip) = public_ipv6.filter(|_| !has_ipv6) {
        retained_terms.push(format!("ip6:{ip}"));
    }

    let mut directive_index = 0;
    for (term_index, term) in raw_terms.iter().enumerate() {
        if syntax::is_modifier(term) {
            retained_terms.push((*term).to_string());
            continue;
        }
        let directive = &current.directives[directive_index];
        let parsed_term_index = directive_terms[directive_index].0;
        debug_assert_eq!(term_index, parsed_term_index);
        directive_index += 1;
        if !managed_directive(directive, applied) {
            retained_terms.push((*term).to_string());
        }
    }

    crate::SpfRecordText::new(
        std::iter::once("v=spf1".to_string())
            .chain(retained_terms)
            .collect::<Vec<_>>()
            .join(" "),
    )
}

/// Replace the SPF value in a TXT RRset, preserving every unrelated value.
///
/// A family passed as `None` is removed from the managed host directives. The
/// previous applied addresses identify which exact directives may be removed.
/// Returns an error when more than one SPF record exists, the current record
/// cannot be parsed, or neither `ipv4` nor `ipv6` is a usable public address.
/// The desired record is appended after unrelated values, matching the previous
/// application's ordering.
pub fn replace_txt_records(
    records: &[String],
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
    applied: &SpfAddresses,
) -> Result<Rewrite, SpfError> {
    if records.iter().filter(|record| is_spf(record)).count() > 1 {
        return Err(SpfError::MultipleSpfRecords);
    }
    let addresses = crate::UsablePublicAddresses::new(
        ipv4.filter(|ip| is_public_ipv4(*ip)),
        ipv6.filter(|ip| is_public_ipv6(*ip)),
    )?;
    replace_txt_records_checked(records, addresses, applied)
}

/// Plan a complete TXT RRset using validated usable addresses.
pub fn replace_txt_records_checked(
    records: &[String],
    addresses: crate::UsablePublicAddresses,
    applied: &SpfAddresses,
) -> Result<Rewrite, SpfError> {
    let spf: Vec<&str> = records
        .iter()
        .filter(|record| is_spf(record))
        .map(String::as_str)
        .collect();
    if spf.len() > 1 {
        return Err(SpfError::MultipleSpfRecords);
    }
    let desired = desired_spf_record_checked(spf.first().copied(), addresses, applied)?;
    let mut rewritten: Vec<String> = records
        .iter()
        .filter(|record| !is_spf(record))
        .cloned()
        .collect();
    rewritten.push(desired.to_string());
    Ok(Rewrite {
        records: rewritten,
        desired,
    })
}

/// Public IPv4 addresses only. Documentation ranges are accepted; loopback,
/// private, link-local, broadcast, unspecified, `0.0.0.0/8` and multicast are
/// rejected.
pub fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.octets()[0] == 0
        || ip.octets()[0] >= 224)
}

/// Public IPv6 addresses only. Documentation ranges are accepted; loopback,
/// unspecified, unique-local, unicast link-local and multicast are rejected.
pub fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || ip.is_multicast())
}

fn managed_directive(directive: &mail_auth::spf::Directive, applied: &SpfAddresses) -> bool {
    matches!(
        (&directive.qualifier, &directive.mechanism),
        (Qualifier::Pass, Mechanism::Ip4 { addr, mask: u32::MAX }) if Some(*addr) == applied.ipv4
    ) || matches!(
        (&directive.qualifier, &directive.mechanism),
        (Qualifier::Pass, Mechanism::Ip6 { addr, mask: u128::MAX }) if Some(*addr) == applied.ipv6
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addresses(ipv4: Option<&str>, ipv6: Option<&str>) -> SpfAddresses {
        SpfAddresses {
            ipv4: ipv4.map(|ip| ip.parse().unwrap()),
            ipv6: ipv6.map(|ip| ip.parse().unwrap()),
        }
    }

    #[test]
    fn v4_only_discovery_removes_the_managed_ipv6_directive() {
        let applied = addresses(Some("203.0.113.7"), Some("2001:db8::7"));
        let result = desired_spf_record(
            Some("v=spf1 ip4:203.0.113.7 ip6:2001:db8::7 include:example.com -all"),
            Some("203.0.113.8".parse().unwrap()),
            None,
            &applied,
        )
        .unwrap();
        assert_eq!(result, "v=spf1 ip4:203.0.113.8 include:example.com -all");
    }

    #[test]
    fn v6_only_discovery_removes_the_managed_ipv4_directive() {
        let applied = addresses(Some("203.0.113.7"), Some("2001:db8::7"));
        let result = desired_spf_record(
            Some("v=spf1 ip4:203.0.113.7 ip6:2001:db8::7 include:example.com -all"),
            None,
            Some("2001:db8::8".parse().unwrap()),
            &applied,
        )
        .unwrap();
        assert_eq!(result, "v=spf1 ip6:2001:db8::8 include:example.com -all");
    }

    #[test]
    fn partial_discovery_preserves_unrelated_networks_and_qualified_directives() {
        let applied = addresses(Some("203.0.113.7"), Some("2001:db8::7"));
        let result = desired_spf_record(
            Some(
                "v=spf1 ip4:203.0.113.7/32 ip6:2001:db8::7/128 ip4:203.0.113.0/24 -ip4:203.0.113.7 ip6:2001:db8::/64 include:example.com ~all",
            ),
            Some("203.0.113.8".parse().unwrap()),
            None,
            &applied,
        )
        .unwrap();
        assert_eq!(
            result,
            "v=spf1 ip4:203.0.113.8 ip4:203.0.113.0/24 -ip4:203.0.113.7 ip6:2001:db8::/64 include:example.com ~all"
        );
    }

    #[test]
    fn an_unavailable_family_is_not_backfilled_from_the_applied_values() {
        let applied = addresses(Some("203.0.113.7"), Some("2001:db8::7"));
        assert!(matches!(
            desired_spf_record(
                Some("v=spf1 ip4:203.0.113.7 ip6:2001:db8::7 -all"),
                None,
                None,
                &applied
            ),
            Err(SpfError::NoPublicAddress)
        ));
    }

    #[test]
    fn replaces_only_saved_pass_host_addresses() {
        let applied = addresses(Some("203.0.113.7"), Some("2001:db8::7"));
        let result = desired_spf_record(
            Some(
                "v=spf1 ip4:203.0.113.7/32 ip6:2001:0db8::7/128 ip4:203.0.113.0/24 -ip4:203.0.113.7 ip6:2001:db8::/64 include:example.com ~all",
            ),
            Some("203.0.113.8".parse().unwrap()),
            Some("2001:db8::8".parse().unwrap()),
            &applied,
        )
        .unwrap();
        assert_eq!(
            result,
            "v=spf1 ip4:203.0.113.8 ip6:2001:db8::8 ip4:203.0.113.0/24 -ip4:203.0.113.7 ip6:2001:db8::/64 include:example.com ~all"
        );
    }

    #[test]
    fn preserves_other_txt_and_is_idempotent() {
        let next = addresses(Some("203.0.113.8"), None);
        let records = vec![
            "site-verification=abc".to_string(),
            "v=spf1 include:example.com -all".to_string(),
        ];
        let rewrite =
            replace_txt_records(&records, next.ipv4, next.ipv6, &SpfAddresses::default()).unwrap();
        assert_eq!(rewrite.records[0], "site-verification=abc");
        let again = replace_txt_records(&rewrite.records, next.ipv4, next.ipv6, &next).unwrap();
        assert_eq!(again.records, rewrite.records);
        assert_eq!(again.desired, rewrite.desired);
    }

    #[test]
    fn creates_missing_spf_and_refuses_multiple_or_invalid_records() {
        let applied = SpfAddresses::default();
        let ip = Some("203.0.113.8".parse().unwrap());
        let rewrite =
            replace_txt_records(&["verification=keep".to_string()], ip, None, &applied).unwrap();
        assert_eq!(rewrite.records.len(), 2);
        assert_eq!(rewrite.desired, "v=spf1 ip4:203.0.113.8 ~all");
        assert!(matches!(
            replace_txt_records(
                &["v=spf1 -all".to_string(), "v=spf1 ~all".to_string()],
                ip,
                None,
                &applied
            ),
            Err(SpfError::MultipleSpfRecords)
        ));
        assert!(matches!(
            replace_txt_records(&["v=spf1 ip4:invalid -all".to_string()], ip, None, &applied),
            Err(SpfError::InvalidRecord(_))
        ));
    }

    #[test]
    fn verification_requires_the_complete_expected_txt_set() {
        let spf = "v=spf1 ip4:203.0.113.8 -all".to_string();
        let other = "verification=keep".to_string();
        assert!(records_equivalent(
            &[spf.clone(), other.clone()],
            &[other.clone(), spf.clone()]
        ));
        assert!(!records_equivalent(
            &[spf.clone(), other.clone()],
            std::slice::from_ref(&spf)
        ));
        assert!(!records_equivalent(
            &[spf.clone(), other.clone()],
            &[other.clone(), other]
        ));
        assert!(!records_equivalent(&[spf], &["v=spf1 -all".to_string()]));
    }

    #[test]
    fn builds_dual_stack_and_preserves_policy() {
        let v4 = Some("8.8.8.7".parse().unwrap());
        let v6 = Some("2606:4700:4700::1111".parse().unwrap());
        assert_eq!(
            desired_spf_record(None, v4, v6, &SpfAddresses::default()).unwrap(),
            "v=spf1 ip4:8.8.8.7 ip6:2606:4700:4700::1111 ~all"
        );
        assert_eq!(
            desired_spf_record(
                Some("v=spf1 include:example.com -all"),
                v4,
                v6,
                &SpfAddresses::default()
            )
            .unwrap(),
            "v=spf1 ip4:8.8.8.7 ip6:2606:4700:4700::1111 include:example.com -all"
        );
        assert_eq!(
            desired_spf_record(
                Some("v=spf1 redirect=example.com"),
                v4,
                None,
                &SpfAddresses::default()
            )
            .unwrap(),
            "v=spf1 ip4:8.8.8.7 redirect=example.com"
        );
    }

    #[test]
    fn rejects_records_without_public_ip_addresses() {
        assert!(matches!(
            desired_spf_record(None, None, None, &SpfAddresses::default()),
            Err(SpfError::NoPublicAddress)
        ));
        assert!(
            desired_spf_record(
                Some("v=spf1 include:example.com -all"),
                Some("192.168.1.2".parse().unwrap()),
                None,
                &SpfAddresses::default()
            )
            .is_err()
        );
        assert!(
            desired_spf_record(
                None,
                None,
                Some("fc00::1".parse().unwrap()),
                &SpfAddresses::default()
            )
            .is_err()
        );
        assert!(
            desired_spf_record(
                None,
                Some("8.8.8.8".parse().unwrap()),
                Some("::1".parse().unwrap()),
                &SpfAddresses::default()
            )
            .unwrap()
            .contains("ip4:8.8.8.8")
        );
    }

    #[test]
    fn recognizes_equivalent_host_addresses_and_rejects_invalid_records() {
        let record = "v=spf1 +ip4:8.8.8.7/32 ip6:2606:4700:4700::1111/128 -all";
        let result = desired_spf_record(
            Some(record),
            Some("8.8.8.7".parse().unwrap()),
            Some("2606:4700:4700::1111".parse().unwrap()),
            &SpfAddresses::default(),
        )
        .unwrap();
        assert_eq!(result.matches("ip4:").count(), 1);
        assert_eq!(result.matches("ip6:").count(), 1);
        assert!(
            desired_spf_record(
                Some("v=spf1 ip4:invalid -all"),
                None,
                None,
                &SpfAddresses::default()
            )
            .is_err()
        );
    }

    #[test]
    fn detects_spf_and_matches_addresses_with_prefixes() {
        assert!(is_spf("v=spf1 -all"));
        assert!(is_spf("V=SPF1 include:example.com"));
        assert!(!is_spf("v=spf1.example.com"));
        assert!(record_includes_ip(
            "v=spf1 ip4:203.0.113.0/24 -all",
            "203.0.113.42".parse().unwrap()
        ));
        assert!(record_includes_ip(
            "v=spf1 +ip6:2001:db8::/32 ~all",
            "2001:db8::1".parse().unwrap()
        ));
        assert!(!record_includes_ip(
            "v=spf1 -ip4:203.0.113.42 -all",
            "203.0.113.42".parse().unwrap()
        ));
        assert!(!record_matches_public_addresses(
            Some("v=spf1 ip4:8.8.8.7 -all"),
            None,
            None
        ));
        assert!(record_matches_public_addresses(
            Some("v=spf1 ip4:8.8.8.7 -all"),
            Some("8.8.8.7".parse().unwrap()),
            None
        ));
    }
}
