//! SSRF protection for live verification.
//!
//! Prevents the scanner from being used as a proxy to attack internal
//! services by blocking requests to private, loopback, and multicast IP ranges.

use dashmap::DashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Cached A/AAAA records expire after this long so a long-running verification
/// session does not pin stale records (and an attacker-influenced wildcard host
/// cannot keep an entry alive indefinitely).
const DNS_CACHE_TTL: Duration = Duration::from_secs(60);

/// Hard cap on distinct host:port entries. Bounds memory regardless of how many
/// unique (e.g. `*.evil.example`) hostnames a scan resolves: once the cap is hit
/// the cache is cleared rather than grown without limit.
const DNS_CACHE_MAX_ENTRIES: usize = 4096;

/// `(inserted_at, resolved addresses)` so expired entries can be detected on read.
type DnsCacheEntry = (Instant, Arc<Vec<SocketAddr>>);

static DNS_CACHE: std::sync::OnceLock<DashMap<String, DnsCacheEntry>> = std::sync::OnceLock::new();

/// Cached DNS resolution to avoid redundant lookups during live API credential validation.
///
/// Entries are bounded both in age (`DNS_CACHE_TTL`) and count
/// (`DNS_CACHE_MAX_ENTRIES`) so the cache cannot grow without limit for the
/// lifetime of the process.
pub async fn resolve_dns_cached(host_port: &str) -> std::io::Result<Vec<SocketAddr>> {
    let cache = DNS_CACHE.get_or_init(DashMap::new);
    if let Some(entry) = cache.get(host_port) {
        let (inserted_at, addrs) = entry.value();
        if inserted_at.elapsed() < DNS_CACHE_TTL {
            return Ok((**addrs).clone());
        }
        // Stale: drop the read guard before mutating to avoid deadlock.
        drop(entry);
        cache.remove(host_port);
    }
    // Perform lookup
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(host_port).await?.collect();
    if !addrs.is_empty() {
        // Bound entry count: clear rather than grow unbounded when the cap is hit.
        if cache.len() >= DNS_CACHE_MAX_ENTRIES {
            cache.clear();
        }
        cache.insert(host_port.to_string(), (Instant::now(), Arc::new(addrs.clone())));
    }
    Ok(addrs)
}

/// Fast bitwise checks on numeric IP values to instantly veto local, private, and loopback IP addresses.
pub fn is_private_ip_addr_fast(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            let val = u32::from_be_bytes(octets);
            // 127.0.0.0/8 (Loopback)
            if val & 0xFF000000 == 0x7F000000 {
                return true;
            }
            // 10.0.0.0/8 (Private A)
            if val & 0xFF000000 == 0x0A000000 {
                return true;
            }
            // 172.16.0.0/12 (Private B)
            if val & 0xFFF00000 == 0xAC100000 {
                return true;
            }
            // 192.168.0.0/16 (Private C)
            if val & 0xFFFF0000 == 0xC0A80000 {
                return true;
            }
            // 169.254.0.0/16 (Link-local)
            if val & 0xFFFF0000 == 0xA9FE0000 {
                return true;
            }
            // 0.0.0.0/8 (Unspecified)
            if val & 0xFF000000 == 0 {
                return true;
            }
            // 224.0.0.0/4 (Multicast)
            if val & 0xF0000000 == 0xE0000000 {
                return true;
            }
            // 100.64.0.0/10 (Carrier-grade NAT)
            if val & 0xFFC00000 == 0x64400000 {
                return true;
            }
            // 255.255.255.255 (Broadcast)
            if val == 0xFFFFFFFF {
                return true;
            }
            false
        }
        IpAddr::V6(ipv6) => {
            let octets = ipv6.octets();
            // ::1 (Loopback)
            if octets == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] {
                return true;
            }
            // :: (Unspecified)
            if octets == [0; 16] {
                return true;
            }
            // fe80::/10 (Link-local)
            if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 {
                return true;
            }
            // fc00::/7 (Unique local)
            if (octets[0] & 0xfe) == 0xfc {
                return true;
            }
            // ff00::/8 (Multicast)
            if octets[0] == 0xff {
                return true;
            }
            false
        }
    }
}

/// Check a resolved IP address against the same private/loopback/multicast rules
/// used for the URL-string check. Used after DNS resolution to defeat DNS
/// rebinding (where attacker.com → 127.0.0.1).
pub fn is_private_ip_addr(ip: &IpAddr) -> bool {
    is_private_ip_addr_fast(ip) || crate::bogon::ip_addr_is_bogon(*ip)
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
                if is_private_ip_addr_fast(&IpAddr::V4(ip))
                    || crate::bogon::ip_addr_is_bogon(IpAddr::V4(ip))
                {
                    return true;
                }
            }
            url::Host::Ipv6(ip) => {
                if is_private_ip_addr_fast(&IpAddr::V6(ip))
                    || crate::bogon::ip_addr_is_bogon(IpAddr::V6(ip))
                {
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
                // hex variant - VRF-001 from the kimi review. The
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
                    if is_private_ip_addr_fast(&IpAddr::V4(ip))
                        || crate::bogon::ip_addr_is_bogon(IpAddr::V4(ip))
                    {
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
