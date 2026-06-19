//! # bogon — canonical SSRF-policy IP classification
//!
//! Single source of truth for the question *"is this address safe to
//! fetch from over the internet, or does it belong to a private /
//! reserved / metadata-leaking range that an SSRF guard must refuse?"*
//! across the Santh scanner fleet.
//!
//! Before this crate existed, four independent implementations of the
//! same predicate lived in the tree — scanclient, wafrift-types,
//! netshift's DNS pool, netshift's DNS cache, and golemn's URL
//! guard. Three of the four had coverage gaps (no CGN, no IETF
//! protocol-assignment range, no benchmark range, no Teredo, no
//! ORCHIDv2, no discard prefix). One had a `::1` IPv6 loopback
//! escape bug. Re-export shims couldn't fix it because scanclient is
//! a heavy reqwest/tokio/rustls/hickory consumer and netshift sits
//! *below* scanclient in the dependency graph — depending on
//! scanclient from netshift would have created a cycle.
//!
//! This crate exists to break that cycle. Pure std-only, zero
//! transitive dep cost, depended on by every consumer that needs an
//! SSRF guard. A future RFC update (a new IETF-reserved range, a
//! new IPv6 documentation prefix) lands here once and propagates
//! everywhere.
//!
//! ## What counts as a bogon
//!
//! "Bogon" here means *not safe to fetch from over the internet
//! unless the operator explicitly opted into private/lab access*.
//! Covers:
//!
//! **IPv4:** RFC 1918 private, loopback, link-local, broadcast,
//! documentation (TEST-NET-1/2/3), unspecified, Carrier-Grade NAT
//! (100.64.0.0/10), IETF protocol assignment (192.0.0.0/24),
//! benchmark (198.18.0.0/15), AWS/GCP/Azure IMDS metadata
//! (169.254.169.254 specifically — but covered by the broader
//! 169.254.0.0/16 link-local rule).
//!
//! **IPv6:** loopback (`::1`), unspecified (`::`), unique-local
//! (`fc00::/7`), link-local (`fe80::/10`), multicast, documentation
//! (`2001:db8::/32`), Teredo (`2001::/32`), ORCHIDv2
//! (`2001:20::/28`), discard prefix (`100::/64`), 6to4 wrapping a
//! bogon IPv4 (`2002::/16`), IPv4-mapped (`::ffff:0:0/96`) and
//! IPv4-compatible (`::a.b.c.d`) wrappings of bogon IPv4.
//!
//! ## What this is *not*
//!
//! Not a public-routing classifier. Multicast IPv4, anycast, and
//! some reserved-but-routable ranges are intentionally allowed
//! because legitimate scanner workloads need them. The function
//! answers exactly *"should SSRF policy refuse this address?"*, not
//! *"is this address globally routable?"*. Consumers that need
//! stricter rules (e.g. keyhog's verifier, which also blocks
//! multicast and broadcast IPv4) should layer their additional
//! checks on top of [`ip_addr_is_bogon`], not fork it.
//!
//! ## The `::1` regression
//!
//! Pre-2026-05-23 the original wafrift donor copy let `::1` past
//! the SSRF guard. The cause: `Ipv6Addr::to_ipv4()` decomposes
//! `::1` to `0.0.0.1`, which is *not* in the IPv4 loopback range
//! (`127.0.0.0/8`). The donor fell through to the v4 fallback and
//! returned `false`. The fix — check `is_loopback()` /
//! `is_unspecified()` before any v4 mapping — is now load-bearing
//! and pinned by [`tests::rejects_ipv6_loopback`].

// This module is `no_std`-clean by construction — it imports only
// `core::net` and forbids unsafe — but `#![no_std]` is a *crate*-level
// attribute and is silently ignored (with a warning) inside a submodule, so
// it is intentionally not declared here. The `core::` imports below are the
// real enforcement.
#![warn(missing_docs)]
#![forbid(unsafe_code)]

use core::net::IpAddr;

/// True if this IP should be blocked when private/upstream lab
/// access is disallowed.
///
/// Covers the union of IPv4 + IPv6 bogon ranges every shipping
/// scanner in the Santh fleet has independently needed to refuse.
/// See [crate-level docs](crate) for the exact coverage list and the
/// non-goals.
///
/// # Examples
///
/// ```
/// use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
/// use keyhog_verifier::testing::{TestApi, VerifierTestApi};
///
/// assert!(TestApi.ip_addr_is_bogon(IpAddr::V4(Ipv4Addr::LOCALHOST)));
/// assert!(TestApi.ip_addr_is_bogon(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
/// assert!(TestApi.ip_addr_is_bogon(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))));
/// assert!(TestApi.ip_addr_is_bogon(IpAddr::V6(Ipv6Addr::LOCALHOST)));
/// assert!(!TestApi.ip_addr_is_bogon(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
/// ```
#[must_use]
pub(crate) fn ip_addr_is_bogon(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            if v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_broadcast()
                || v.is_documentation()
                // 0.0.0.0/8 "this network" (RFC 1122 §3.2.1.3), not just the
                // single 0.0.0.0 that `is_unspecified()` matches. 0.0.0.1 et al.
                // are non-routable and an SSRF target (parity with the fast path
                // `is_private_ip_addr_fast`, which masks `val & 0xFF000000 == 0`).
                || v.octets()[0] == 0
            {
                return true;
            }
            let octets = v.octets();
            if octets[0] == 100 && (octets[1] & 0xc0) == 0x40 {
                return true; // 100.64.0.0/10 CGN
            }
            if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
                return true; // 192.0.0.0/24
            }
            if octets[0] == 198 && (octets[1] & 0xfe) == 18 {
                return true; // 198.18.0.0/15
            }
            // Link-local + metadata (IMDS) — explicit for stealth
            // parity with proxy audits.
            if octets[0] == 169 && octets[1] == 254 {
                return true;
            }
            false
        }
        IpAddr::V6(v) => {
            // IPv6-specific bogon checks come FIRST: `::1` (loopback)
            // and `::` (unspecified) decompose via `to_ipv4()` to
            // 0.0.0.1 / 0.0.0.0, neither of which matches the IPv4
            // loopback predicate (127/8). Without this short-circuit
            // the v4 fallback would let `::1` past the SSRF guard
            // — a real bug the original donor copy carried before
            // 2026-05-23.
            if v.is_loopback() || v.is_unspecified() {
                return true;
            }
            if let Some(mapped) = v.to_ipv4_mapped() {
                return ip_addr_is_bogon(IpAddr::V4(mapped));
            }
            if let Some(compat) = v.to_ipv4() {
                return ip_addr_is_bogon(IpAddr::V4(compat));
            }
            let segs = v.segments();
            if segs[0] == 0x2002 {
                let v4 = core::net::Ipv4Addr::new(
                    (segs[1] >> 8) as u8,
                    (segs[1] & 0xff) as u8,
                    (segs[2] >> 8) as u8,
                    (segs[2] & 0xff) as u8,
                );
                if ip_addr_is_bogon(IpAddr::V4(v4)) {
                    return true;
                }
            }
            if segs[0] == 0x2001 && segs[1] == 0x0db8 {
                return true; // RFC 3849 documentation
            }
            if segs[0] == 0x2001 && segs[1] == 0x0000 {
                return true; // Teredo (RFC 4380)
            }
            if segs[0] == 0x2001 && (segs[1] & 0xfff0) == 0x0020 {
                return true; // ORCHIDv2 (RFC 7343)
            }
            if segs[0] == 0x0100 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0 {
                return true; // 100::/64 discard (RFC 6666)
            }
            v.is_loopback()
                || v.is_multicast()
                || v.is_unspecified()
                || v.is_unique_local()
                || v.is_unicast_link_local()
        }
    }
}
