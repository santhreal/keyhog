//! SSRF protection for live verification.
//!
//! Prevents the scanner from being used as a proxy to attack internal
//! services by blocking requests to private, loopback, and multicast IP ranges.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::Host;

/// Check a resolved IP address against the same private/loopback/multicast rules
/// used for the URL-string check. Used after DNS resolution to defeat DNS
/// rebinding (where attacker.com → 127.0.0.1).
pub fn is_private_ip_addr(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_ipv4(*v4),
        IpAddr::V6(v6) => is_private_ipv6(*v6),
    }
}

/// Returns true if the URL points to a private or loopback address.
pub fn is_private_url(url_str: &str) -> bool {
    let url = match reqwest::Url::parse(url_str) {
        Ok(u) => u,
        Err(_) => return true, // Block malformed URLs
    };

    // If it's a domain name, we can't easily check without resolution.
    // However, we can block explicit IP hosts.
    if let Some(host) = url.host() {
        match host {
            Host::Ipv4(ip) => {
                if is_private_ipv4(ip) {
                    return true;
                }
            }
            Host::Ipv6(ip) => {
                if is_private_ipv6(ip) {
                    return true;
                }
            }
            Host::Domain(d) => {
                if d == "localhost"
                    || d.ends_with(".local")
                    || d.ends_with(".internal")
                    || d.ends_with(".localdomain")
                {
                    return true;
                }

                // Block integer-encoded IP addresses (e.g. http://2130706433/)
                if let Some(ip) = parse_ipv4_host(d) {
                    if is_private_ipv4(ip) {
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

fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip == Ipv4Addr::new(0, 0, 0, 0)
        || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64) // CGNAT
}

fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    ip.is_loopback()
        || is_ipv6_unique_local(&ip)
        || is_ipv6_link_local(&ip)
        || ip.is_multicast()
        || ip == Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)
        || is_ipv6_embedding_private_ipv4(&ip)
        || ip.segments()[0] == 0x2002 // 6to4
}

/// Catches ALL IPv6 addresses that embed a private IPv4:
/// - IPv4-mapped: ::ffff:127.0.0.1
/// - IPv4-compatible (deprecated): ::127.0.0.1
/// - IPv4-translated: ::ffff:0:127.0.0.1
/// - NAT64 well-known prefix: 64:ff9b::127.0.0.1
fn is_ipv6_embedding_private_ipv4(ip: &Ipv6Addr) -> bool {
    // Use Rust's built-in mapping for ::ffff:x.x.x.x
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_private_ipv4(ipv4);
    }
    // IPv4-compatible (deprecated but still parseable): ::x.x.x.x
    if let Some(ipv4) = ip.to_ipv4() {
        if is_private_ipv4(ipv4) {
            return true;
        }
    }
    let segs = ip.segments();
    // IPv4-translated: ::ffff:0:x.x.x.x (segments [0,0,0,0,0xffff,0,hi,lo])
    if segs[0..4] == [0, 0, 0, 0] && segs[4] == 0xffff && segs[5] == 0 {
        let ipv4 = Ipv4Addr::new(
            (segs[6] >> 8) as u8,
            segs[6] as u8,
            (segs[7] >> 8) as u8,
            segs[7] as u8,
        );
        if is_private_ipv4(ipv4) {
            return true;
        }
    }
    // NAT64 well-known prefix: 64:ff9b::x.x.x.x
    if segs[0] == 0x0064 && segs[1] == 0xff9b && segs[2..6] == [0, 0, 0, 0] {
        let ipv4 = Ipv4Addr::new(
            (segs[6] >> 8) as u8,
            segs[6] as u8,
            (segs[7] >> 8) as u8,
            segs[7] as u8,
        );
        if is_private_ipv4(ipv4) {
            return true;
        }
    }

    // Aggressive fallback: block ANY IPv6 address ending in a private IPv4 address
    let ipv4_suffix = Ipv4Addr::new(
        (segs[6] >> 8) as u8,
        segs[6] as u8,
        (segs[7] >> 8) as u8,
        segs[7] as u8,
    );
    if is_private_ipv4(ipv4_suffix) {
        return true;
    }

    false
}

fn is_ipv6_unique_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

fn is_ipv6_link_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
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

pub fn parse_ipv4_host(host: &str) -> Option<Ipv4Addr> {
    if let Ok(n) = host.parse::<u32>() {
        return Some(Ipv4Addr::from(n));
    }
    host.parse::<Ipv4Addr>().ok()
}
