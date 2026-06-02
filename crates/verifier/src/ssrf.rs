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
        cache.insert(
            host_port.to_string(),
            (Instant::now(), Arc::new(addrs.clone())),
        );
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
            // 240.0.0.0/4 (Reserved, RFC 1112 "future use" / Class E).
            // This range is not globally routable and includes the limited
            // broadcast address 255.255.255.255 (0xFFFFFFFF) as its top host.
            // A defense-in-depth SSRF guard blocks the whole reserved block
            // fail-closed — nothing legitimate is reachable there, and decimal
            // IP forms like `http://4294967294/` (255.255.255.254) must not slip
            // through just because they aren't the exact broadcast value.
            if val & 0xF0000000 == 0xF0000000 {
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
                } else if let Ok(ip) = d.parse::<Ipv4Addr>() {
                    Some(ip)
                } else {
                    // Abbreviated dotted forms that glibc/getaddrinfo accept but
                    // `Ipv4Addr::parse` rejects (it requires exactly 4 octets):
                    //
                    //   - 2-part:  http://127.1        → 127.0.0.1
                    //   - 3-part:  http://172.16.1     → 172.16.0.1
                    //
                    // In classic inet_aton semantics the final field packs into
                    // the trailing low bytes, so the previous octets are the high
                    // bytes and the last field fills the remainder. Without this
                    // the URL-string SSRF gate let `https://127.1/` through, and
                    // on the proxy path (which skips the post-resolution IP veto)
                    // that was the only gate.
                    canonicalize_short_form_ipv4(d)
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

/// Canonicalize an abbreviated dotted IPv4 (`inet_aton`-style) into a full
/// [`Ipv4Addr`]. Handles the 1-, 2-, and 3-part short forms a permissive
/// resolver accepts:
///
///   - 1-part  → handled earlier as a bare integer (`http://2130706433`).
///   - 2-part  `a.b`     → `a` is octet 0, `b` packs into the low 3 bytes
///                          (`127.1`     → `127.0.0.1`).
///   - 3-part  `a.b.c`   → `a`, `b` are octets 0/1, `c` packs into the low
///                          2 bytes (`172.16.1` → `172.16.0.1`).
///   - 4-part  `a.b.c.d` → standard dotted-quad (already covered by
///                          `Ipv4Addr::parse`, so not re-handled here).
///
/// Each part is parsed per `inet_aton` radix rules: `0x`/`0X` prefix → hex,
/// a leading `0` → octal, otherwise decimal. Any out-of-range field or parse
/// failure yields `None` (the caller then falls through to its other checks).
fn canonicalize_short_form_ipv4(domain: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() < 2 || parts.len() > 3 {
        return None;
    }
    let values: Option<Vec<u32>> = parts.iter().map(|p| parse_ip_field(p)).collect();
    let values = values?;
    let n = values.len();
    // Leading fields each occupy one byte (must fit in a u8).
    let mut acc: u32 = 0;
    for &leading in &values[..n - 1] {
        if leading > 0xFF {
            return None;
        }
        acc = (acc << 8) | leading;
    }
    // The final field packs into the remaining low bytes.
    let remaining_bytes = 4 - (n - 1);
    let last = values[n - 1];
    let max_last = if remaining_bytes >= 4 {
        u32::MAX
    } else {
        (1u32 << (8 * remaining_bytes as u32)) - 1
    };
    if last > max_last {
        return None;
    }
    acc = (acc << (8 * remaining_bytes as u32)) | last;
    Some(Ipv4Addr::from(acc))
}

/// Parse a single dotted-IP field using `inet_aton` radix rules.
fn parse_ip_field(part: &str) -> Option<u32> {
    if part.is_empty() {
        return None;
    }
    if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
        if hex.is_empty() {
            return None;
        }
        u32::from_str_radix(hex, 16).ok()
    } else if part.len() > 1 && part.starts_with('0') {
        u32::from_str_radix(part, 8).ok()
    } else {
        part.parse::<u32>().ok()
    }
}

fn looks_like_malformed_ip(domain: &str) -> bool {
    let parts: Vec<&str> = domain.split('.').collect();
    // Domains with 4+ dot-separated parts where every part is an octet-shaped
    // token a permissive resolver might canonicalize into an IP: decimal,
    // `0x`-hex, or a (always-invalid) negative octet. The `f` in `0x7f` must
    // count - the pre-fix `digit|-|x|X` set excluded a..f, leaving an SSRF
    // bypass via `0x7f.0.0.-1`. `is_ascii_hexdigit` subsumes the old digit
    // check, so this only widens blocking (fail closed).
    if parts.len() >= 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.chars()
                    .all(|c| c.is_ascii_hexdigit() || c == '-' || c == 'x' || c == 'X')
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
