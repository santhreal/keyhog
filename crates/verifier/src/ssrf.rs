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

/// Canonical verifier IP-address refusal policy.
///
/// The fleet-wide bogon table owns private, loopback, link-local,
/// documentation, benchmark, protocol-assignment, metadata, IPv6 wrapping, and
/// other reserved ranges. The verifier adds the ranges it deliberately refuses
/// even though `bogon` leaves them available for consumers with different
/// routing policy: IPv4 multicast and the IPv4 Class-E reserved block.
#[inline]
fn verifier_blocks_ip_addr(ip: IpAddr) -> bool {
    if crate::bogon::ip_addr_is_bogon(ip) {
        return true;
    }
    match ip {
        IpAddr::V4(ipv4) => ipv4.is_multicast() || ipv4.octets()[0] >= 240,
        IpAddr::V6(_) => false,
    }
}

/// Compatibility alias for callers that still import the historical fast-path
/// name. It now returns the single verifier IP policy instead of a partial
/// pre-bogon subset.
#[inline]
pub fn is_private_ip_addr_fast(ip: &IpAddr) -> bool {
    verifier_blocks_ip_addr(*ip)
}

/// Check a resolved IP address against the same private/loopback/multicast rules
/// used for the URL-string check. Used after DNS resolution to defeat DNS
/// rebinding (where attacker.com → 127.0.0.1).
#[inline]
pub fn is_private_ip_addr(ip: &IpAddr) -> bool {
    verifier_blocks_ip_addr(*ip)
}

/// Returns true if the URL points to a private or loopback address.
pub fn is_private_url(url_str: &str) -> bool {
    let url = match url::Url::parse(url_str) {
        Ok(u) => u,
        // Law 10: fail CLOSED — an unparseable URL is treated as private/blocked
        // (`return true`), never allowed through. This is the loud security
        // decision, not a swallowed error: the verifier refuses the request.
        Err(_) => return true, // LAW10: fail-CLOSED — unparseable URL is blocked, never allowed
    };

    if !matches!(url.scheme(), "http" | "https") {
        return true; // LAW10: fail-CLOSED — verifier/web fetch SSRF gates only allow DNS-screenable http(s) URLs
    }

    let Some(host) = url.host() else {
        return true; // LAW10: fail-CLOSED — hostless URLs cannot be DNS-screened, so they are blocked
    };

    match host {
        url::Host::Ipv4(ip) => {
            if verifier_blocks_ip_addr(IpAddr::V4(ip)) {
                return true;
            }
        }
        url::Host::Ipv6(ip) => {
            if verifier_blocks_ip_addr(IpAddr::V6(ip)) {
                return true;
            }
        }
        url::Host::Domain(d) => {
            if !d.contains('.')
                || d == "localhost"
                || d.ends_with(".localhost")
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
            let maybe_ip = if let Some(hex) = d.strip_prefix("0x").or_else(|| d.strip_prefix("0X"))
            {
                // Law 10: a `None` here is NOT a swallowed block-decision — it
                // only means "this token is not a parseable hex integer-IP",
                // so `maybe_ip` stays `None` and the host is treated as a real
                // domain. That domain still gets DNS-resolved and re-screened
                // against `is_private_ip_addr` post-resolution (rebinding
                // defense), AND `looks_like_malformed_ip` below independently
                // blocks octet-shaped evasion. No SSRF target is let through.
                u32::from_str_radix(hex, 16).ok().map(Ipv4Addr::from) // LAW10: fail-open to domain (see above) — post-resolution veto still gates it
            } else if d.starts_with('0') && d.len() > 1 && d.chars().all(|c| c.is_ascii_digit()) {
                // Law 10: see above — a failed octal parse yields `None`
                // (treat as domain), not an allow; post-resolution veto +
                // `looks_like_malformed_ip` still gate it.
                u32::from_str_radix(d, 8).ok().map(Ipv4Addr::from) // LAW10: fail-open to domain (see above) — post-resolution veto still gates it
            } else if let Ok(n) = d.parse::<u32>() {
                // LAW10: parse failure falls through to strict IP/domain SSRF checks below; no target is allowed by this branch.
                Some(Ipv4Addr::from(n))
            } else if let Ok(ip) = d.parse::<Ipv4Addr>() {
                // LAW10: parse failure falls through to strict IP/domain SSRF checks below; no target is allowed by this branch.
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
                if verifier_blocks_ip_addr(IpAddr::V4(ip)) {
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
    let mut values = [0u32; 3];
    let mut len = 0usize;
    for part in domain.split('.') {
        if len == values.len() {
            return None;
        }
        values[len] = parse_ip_field(part)?;
        len += 1;
    }
    if len < 2 {
        return None;
    }
    // Leading fields each occupy one byte (must fit in a u8).
    let mut acc: u32 = 0;
    for &leading in &values[..len - 1] {
        if leading > 0xFF {
            return None;
        }
        acc = (acc << 8) | leading;
    }
    // The final field packs into the remaining low bytes.
    let remaining_bytes = 4 - (len - 1);
    let last = values[len - 1];
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
        // Law 10: a `None` field-parse is recall/security-safe — it aborts
        // short-form IPv4 canonicalization (so the host is treated as a domain,
        // not silently allowed). The caller's `looks_like_malformed_ip` +
        // post-resolution `is_private_ip_addr` veto still block evasion forms.
        u32::from_str_radix(hex, 16).ok() // LAW10: fail-open field-parse (see above) — never an allow
    } else if part.len() > 1 && part.starts_with('0') {
        // Law 10: see above — failed octal field-parse aborts canonicalization
        // to `None`, never an allow.
        u32::from_str_radix(part, 8).ok() // LAW10: fail-open field-parse (see above) — never an allow
    } else {
        // Law 10: see above — failed decimal field-parse aborts to `None`.
        part.parse::<u32>().ok() // LAW10: fail-open field-parse (see above) — never an allow
    }
}

fn looks_like_malformed_ip(domain: &str) -> bool {
    let mut part_count = 0usize;
    let mut all_octet_shaped = true;
    let mut all_octal_shaped = true;
    for part in domain.split('.') {
        part_count += 1;
        if part.is_empty() {
            all_octet_shaped = false;
            all_octal_shaped = false;
            continue;
        }
        if !part
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '-' || c == 'x' || c == 'X')
        {
            all_octet_shaped = false;
        }
        if !(part.starts_with('0') && part.len() > 1 && part.chars().all(|c| c.is_ascii_digit())) {
            all_octal_shaped = false;
        }
    }
    // Domains with 4+ dot-separated parts where every part is an octet-shaped
    // token a permissive resolver might canonicalize into an IP: decimal,
    // `0x`-hex, or a (always-invalid) negative octet. The `f` in `0x7f` must
    // count - the pre-fix `digit|-|x|X` set excluded a..f, leaving an SSRF
    // bypass via `0x7f.0.0.-1`. `is_ascii_hexdigit` subsumes the old digit
    // check, so this only widens blocking (fail closed).
    if part_count >= 4 && all_octet_shaped {
        return true;
    }
    // Octal-encoded IP: starts with 0 and contains dots (e.g. 0177.0.0.1)
    if part_count == 4 && all_octal_shaped {
        return true;
    }
    false
}
