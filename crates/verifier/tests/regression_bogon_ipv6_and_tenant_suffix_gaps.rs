//! Backlog-drain: 5 verifier SSRF/allowlist test-gaps (BACKLOG rows for
//! `bogon.rs:{146,189,232}` + `domain_allowlist.rs:{115,158}`). Each asserts a
//! concrete security decision that was code-present but uncovered:
//!
//!   * an IPv4-mapped IPv6 wrapper of a bogon (`::ffff:127.0.0.1`) is a bogon
//!     the mapped-decompose branch (`bogon.rs:146`); an SSRF guard that missed
//!     it would let a loopback target through in mapped form;
//!   * deprecated site-local `fec0::/10` is a bogon (`bogon.rs:189`);
//!   * a NAT64 wrapper (well-known `64:ff9b::/96` AND Local-Use `64:ff9b:1::/48`)
//!     of a private IPv4 is a bogon, it round-trips to the private v4 at the
//!     gateway (`bogon.rs:232` / `nat64_embedded_ipv4`);
//!   * `effective_allowlist` returns `None` for an empty-service spec with no
//!     explicit domains (`domain_allowlist.rs:115`), fail-closed, no domain is
//!     implicitly licensed;
//!   * an EXACT-ONLY shared-tenant suffix (e.g. `myshopify.com`) allows ONLY the
//!     apex, never a `*.suffix` subdomain that belongs to a DIFFERENT tenant
//!     (`domain_allowlist.rs:158`) (the anti-cross-tenant-exfil guard).
//!
//! Reached through the public `VerifierTestApi` facade (the predicates are
//! `pub(crate)`), matching `new_verifier_bogon_ssrf.rs`.

use keyhog_core::VerifySpec;
use keyhog_verifier::testing::{TestApi, VerifierTestApi};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn v6(a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h))
}

/// BACKLOG bogon.rs:146, an IPv4-mapped IPv6 decomposes to its embedded v4 and
/// inherits that v4's bogon verdict.
#[test]
fn mapped_ipv6_inherits_embedded_v4_bogon_verdict() {
    // ::ffff:127.0.0.1 (mapped loopback is a bogon).
    assert!(TestApi.ip_addr_is_bogon(v6(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001)));
    // ::ffff:10.0.0.1 (mapped RFC1918 is a bogon).
    assert!(TestApi.ip_addr_is_bogon(v6(0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001)));
    // ::ffff:8.8.8.8, mapped PUBLIC address is NOT a bogon (the verdict really
    // follows the embedded v4, it is not a blanket "all mapped are bogon").
    assert!(!TestApi.ip_addr_is_bogon(v6(0, 0, 0, 0, 0, 0xffff, 0x0808, 0x0808)));
}

/// BACKLOG bogon.rs:189 (deprecated site-local `fec0::/10` is a bogon).
#[test]
fn site_local_fec0_ipv6_is_bogon() {
    assert!(TestApi.ip_addr_is_bogon(v6(0xfec0, 0, 0, 0, 0, 0, 0, 1)));
    // Top of the /10 (0xfeff still masks to 0xfec0) is also site-local.
    assert!(TestApi.ip_addr_is_bogon(v6(0xfeff, 0, 0, 0, 0, 0, 0, 1)));
    // A public global-unicast address (2606:4700:4700::1111, Cloudflare) is not.
    assert!(!TestApi.ip_addr_is_bogon(v6(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)));
}

/// BACKLOG bogon.rs:232, a NAT64 wrapper of a private IPv4 is a bogon (both the
/// well-known `64:ff9b::/96` and the Local-Use `64:ff9b:1::/48` embeddings),
/// because it round-trips to that private v4 once the gateway translates.
#[test]
fn nat64_embedded_private_v4_is_bogon() {
    // Well-known /96: 64:ff9b::10.0.0.1 (v4 in the low 32 bits).
    assert!(TestApi.ip_addr_is_bogon(v6(0x0064, 0xff9b, 0, 0, 0, 0, 0x0a00, 0x0001)));
    // Local-Use /48: 64:ff9b:1::/48 embedding 10.0.0.1 (RFC 6052 §2.2 layout:
    // segs[3]=0a00, segs[4] low byte=00, segs[5] high byte=01 → 10.0.0.1).
    assert!(TestApi.ip_addr_is_bogon(v6(0x0064, 0xff9b, 0x0001, 0x0a00, 0x0000, 0x0100, 0, 0)));
    // Local-Use /48 embedding a PUBLIC v4 (8.8.8.8) is NOT a bogon, the verdict
    // follows the embedded address, so a NAT64 wrapper is not blanket-blocked.
    assert!(!TestApi.ip_addr_is_bogon(v6(0x0064, 0xff9b, 0x0001, 0x0808, 0x0008, 0x0800, 0, 0)));
    // Sanity: the embedded v4 is exactly what the wrapper resolves to.
    assert!(TestApi.ip_addr_is_bogon(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    assert!(!TestApi.ip_addr_is_bogon(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
}

/// BACKLOG domain_allowlist.rs:115, with no explicit `allowed_domains` and an
/// EMPTY `service`, there is no builtin allowlist to inherit, so
/// `effective_allowlist` is `None` (fail-closed: nothing implicitly licensed).
#[test]
fn effective_allowlist_is_none_for_empty_service() {
    let empty = VerifySpec::default();
    assert!(empty.service.is_empty());
    assert_eq!(TestApi.effective_allowlist(&empty), None);

    // With an explicit allowed_domains list, it is Some(that list), proving the
    // None above is specifically the empty-service/no-domains case.
    let explicit = VerifySpec {
        allowed_domains: vec!["api.example.com".to_string()],
        ..VerifySpec::default()
    };
    assert_eq!(
        TestApi.effective_allowlist(&explicit),
        Some(vec!["api.example.com".to_string()])
    );
}

/// BACKLOG domain_allowlist.rs:158, an EXACT-ONLY shared-tenant suffix allows
/// ONLY its apex, never a subdomain (which would belong to another tenant),
/// whereas an ordinary allowlisted domain DOES allow its subdomains.
#[test]
fn exact_only_shared_tenant_suffix_rejects_subdomains() {
    let shared = ["myshopify.com".to_string()];
    // The apex itself is allowed (exact match).
    assert!(TestApi.host_is_allowed("myshopify.com", &shared));
    // A subdomain of the shared-tenant suffix is REJECTED, it is a different
    // tenant's store, not the credential's owner.
    assert!(!TestApi.host_is_allowed("evil.myshopify.com", &shared));

    // Contrast: an ORDINARY (non-shared-tenant) allowlisted domain allows its
    // subdomains, so the rejection above is specifically the exact-only guard.
    let ordinary = ["example.com".to_string()];
    assert!(TestApi.host_is_allowed("example.com", &ordinary));
    assert!(TestApi.host_is_allowed("api.example.com", &ordinary));
}
