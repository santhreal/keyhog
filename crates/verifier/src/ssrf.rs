//! SSRF protection for live verification.
//!
//! Prevents the scanner from being used as a proxy to attack internal
//! services by blocking requests to private, loopback, and multicast IP ranges.

use std::net::{IpAddr, Ipv4Addr};

/// Check a resolved IP address against the same private/loopback/multicast rules
/// used for the URL-string check. Used after DNS resolution to defeat DNS
/// rebinding (where attacker.com → 127.0.0.1).
pub fn is_private_ip_addr(ip: &IpAddr) -> bool {
    bogon::ip_addr_is_bogon(*ip)
}

/// Returns true if the URL points to a private or loopback address.
pub fn is_private_url(url_str: &str) -> bool {
    let url = match url::Url::parse(url_str) {
        Ok(u) => u,
        Err(_) => return true, // Block malformed URLs
    };

    if let Some(host) = url.host() {
        match host {
            url::Host::Ipv4(ip) => {
                if bogon::ip_addr_is_bogon(IpAddr::V4(ip)) {
                    return true;
                }
            }
            url::Host::Ipv6(ip) => {
                if bogon::ip_addr_is_bogon(IpAddr::V6(ip)) {
                    return true;
                }
            }
            url::Host::Domain(d) => {
                if d == "localhost"
                    || d.ends_with(".local")
                    || d.ends_with(".internal")
                    || d.ends_with(".localdomain")
                {
                    return true;
                }

                // Block integer-encoded IP addresses across every radix
                // a permissive resolver might canonicalize:
                //
                //   - Decimal:  http://2130706433/                  → 127.0.0.1
                //   - Hex:      http://0x7f000001/                  → 127.0.0.1
                //   - Octal:    http://017700000001/                → 127.0.0.1
                //   - Dotted:   http://127.0.0.1/                   (Ipv4Addr::parse)
                //
                // glibc's getaddrinfo + several musl-based resolvers
                // accept all four. Blocking only the decimal form
                // (the pre-fix behavior) left an SSRF bypass via the
                // hex variant — VRF-001 from the kimi review. The
                // explicit `0x`-prefixed `from_str_radix(16)` covers
                // that gap; the leading-zero radix-8 parse covers the
                // octal variant for completeness.
                let maybe_ip = if let Some(hex) =
                    d.strip_prefix("0x").or_else(|| d.strip_prefix("0X"))
                {
                    u32::from_str_radix(hex, 16).ok().map(Ipv4Addr::from)
                } else if d.starts_with('0') && d.len() > 1 && d.chars().all(|c| c.is_ascii_digit())
                {
                    u32::from_str_radix(d, 8).ok().map(Ipv4Addr::from)
                } else if let Ok(n) = d.parse::<u32>() {
                    Some(Ipv4Addr::from(n))
                } else {
                    d.parse::<Ipv4Addr>().ok()
                };
                if let Some(ip) = maybe_ip {
                    if bogon::ip_addr_is_bogon(IpAddr::V4(ip)) {
                        return true;
                    }
                }

                // Block domains that look like malformed IPs (negative octets, too many dots, etc.)
                // These are likely evasion attempts.
                if looks_like_malformed_ip(d) {
                    return true;
                }
            }
        }
    }

    false
}

fn looks_like_malformed_ip(domain: &str) -> bool {
    let parts: Vec<&str> = domain.split('.').collect();
    // Domains with 4+ dot-separated parts where all parts are numeric-ish (digits, minus, hex prefix)
    if parts.len() >= 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.chars()
                    .all(|c| c.is_ascii_digit() || c == '-' || c == 'x' || c == 'X')
        })
    {
        return true;
    }
    // Octal-encoded IP: starts with 0 and contains dots (e.g. 0177.0.0.1)
    if parts.len() == 4
        && parts
            .iter()
            .all(|p| p.starts_with('0') && p.len() > 1 && p.chars().all(|c| c.is_ascii_digit()))
    {
        return true;
    }
    false
}
