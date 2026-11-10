//! Checks syntax that the upstream SPF parser intentionally accepts leniently.
use crate::SpfError;
use std::net::{Ipv4Addr, Ipv6Addr};

pub(super) fn is_modifier(term: &str) -> bool {
    term.split_once('=').is_some_and(|(name, _)| {
        name.bytes().next().is_some_and(|b| b.is_ascii_alphabetic())
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    })
}

pub(crate) fn parse(record: &str) -> Result<mail_auth::spf::SpfRecord, SpfError> {
    use mail_auth::dns::TxtRecordParser;
    validate(record)?;
    // The parser rejects some legal extension modifier names/values. Exclude
    // those only from its parse view; the original terms remain in the rewrite.
    let parse_view = record
        .split_ascii_whitespace()
        .enumerate()
        .filter(|(index, term)| {
            *index == 0
                || !is_modifier(term)
                || term.split_once('=').is_some_and(|(name, _)| {
                    name.eq_ignore_ascii_case("redirect") || name.eq_ignore_ascii_case("exp")
                })
        })
        .map(|(_, term)| term)
        .collect::<Vec<_>>()
        .join(" ");
    mail_auth::spf::SpfRecord::parse(parse_view.as_bytes()).map_err(|error| {
        SpfError::InvalidRecord(format!("Could not parse the SPF record: {error}"))
    })
}

fn validate(record: &str) -> Result<(), SpfError> {
    let invalid =
        |term: &str| SpfError::InvalidRecord(format!("Invalid SPF syntax in term {term:?}."));
    if !crate::is_spf(record) {
        return Err(invalid(record));
    }
    for term in record.split_ascii_whitespace().skip(1) {
        // Unknown modifiers are explicitly extensible in SPF, unlike mechanisms.
        if is_modifier(term) {
            if !macro_string(term.split_once('=').unwrap().1) {
                return Err(invalid(term));
            }
            continue;
        }
        let mechanism = term.strip_prefix(['+', '-', '~', '?']).unwrap_or(term);
        let name_end = mechanism.find([':', '/']).unwrap_or(mechanism.len());
        let name = mechanism[..name_end].to_ascii_lowercase();
        let rest = &mechanism[name_end..];
        let valid = match name.as_str() {
            "all" => rest.is_empty(),
            "ip4" | "ip6" => rest.strip_prefix(':').is_some_and(|value| {
                let (address, cidr) = value
                    .split_once('/')
                    .map_or((value, None), |(a, c)| (a, Some(c)));
                if name == "ip4" {
                    address.parse::<Ipv4Addr>().is_ok() && cidr.is_none_or(|c| prefix(c, 32, 2))
                } else {
                    address.parse::<Ipv6Addr>().is_ok() && cidr.is_none_or(|c| prefix(c, 128, 3))
                }
            }),
            "include" | "exists" => rest
                .strip_prefix(':')
                .is_some_and(|domain| !domain.is_empty()),
            "ptr" => {
                rest.is_empty()
                    || rest
                        .strip_prefix(':')
                        .is_some_and(|domain| !domain.is_empty())
            }
            "a" | "mx" => address_mechanism(rest),
            _ => false,
        };
        if !valid {
            return Err(invalid(term));
        }
    }
    Ok(())
}

fn prefix(value: &str, maximum: u16, digits: usize) -> bool {
    !value.is_empty()
        && value.len() <= digits
        && value.bytes().all(|b| b.is_ascii_digit())
        && value.parse::<u16>().is_ok_and(|n| n <= maximum)
}

fn address_mechanism(rest: &str) -> bool {
    // A slash inside a domain-spec macro is not a CIDR delimiter.
    let mut in_macro = false;
    let mut previous = None;
    let cidr_start = rest.char_indices().find_map(|(index, ch)| {
        if previous == Some('%') && ch == '{' {
            in_macro = true;
        }
        if ch == '}' {
            in_macro = false;
        }
        previous = Some(ch);
        (ch == '/' && !in_macro).then_some(index)
    });
    let (domain, cidr) = cidr_start.map_or((rest, ""), |index| rest.split_at(index));
    if !domain.is_empty()
        && !domain
            .strip_prefix(':')
            .is_some_and(|value| !value.is_empty())
    {
        return false;
    }
    if cidr.is_empty() {
        return true;
    }
    if let Some(v6) = cidr.strip_prefix("//") {
        return prefix(v6, 128, 3);
    }
    let Some(v4) = cidr.strip_prefix('/') else {
        return false;
    };
    if let Some((v4, v6)) = v4.split_once("//") {
        prefix(v4, 32, 2) && prefix(v6, 128, 3)
    } else {
        prefix(v4, 32, 2)
    }
}

fn macro_string(value: &str) -> bool {
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if !(b'!'..=b'~').contains(&byte) {
            return false;
        }
        if byte != b'%' {
            continue;
        }
        match bytes.next() {
            Some(b'%' | b'_' | b'-') => (),
            Some(b'{') => {
                if !bytes
                    .next()
                    .is_some_and(|b| b"slodipvhcrtSLODIPVHCRT".contains(&b))
                {
                    return false;
                }
                let mut next = bytes.next();
                while next.is_some_and(|b| b.is_ascii_digit()) {
                    next = bytes.next();
                }
                if next == Some(b'r') {
                    next = bytes.next();
                }
                while next.is_some_and(|b| b".-+,/_=".contains(&b)) {
                    next = bytes.next();
                }
                if next != Some(b'}') {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}
