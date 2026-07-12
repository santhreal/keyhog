//! Regression + adversarial suite for the verifier network-safety fix wave.
//!
//! Four cohesive SSRF/robustness fixes in `crates/verifier/src`, each pinned by
//! an adversarial case that FAILS pre-fix plus a positive twin so the fix cannot
//! be "passed" by over-blocking:
//!
//!  1. `bogon.rs` — NAT64 decomposition missed the RFC 8215 Local-Use prefix
//!     `64:ff9b:1::/48`; an internal IPv4 embedded in it slipped the SSRF guard.
//!  2. `oob/client.rs` `collector_http_client` — the proxy-configured client
//!     skipped the resolved-IP screen (proxy-SSRF / DNS rebinding).
//!  3. `oob/client.rs` `normalize_server` — kept path/userinfo, minting a
//!     malformed callback host after sanitization.
//!  4. `rate_limit.rs` — `Instant::now() - interval` underflow-panicked on a
//!     low-uptime host (fresh container).
//!
//! Oracles are exact: each address falls in a named RFC range, each host string
//! has a known safe normal form, each screen verdict is `Ok`/`Err` by policy.
//! No `is_ok()` / `!is_empty()` decoration.

use keyhog_verifier::ssrf::is_private_url;
use keyhog_verifier::testing::{redact_interactsh_error, TestApi, VerifierTestApi};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

// ===========================================================================
// 1. NAT64 Local-Use prefix 64:ff9b:1::/48 (RFC 8215) — the fix
// ===========================================================================

/// 64:ff9b:1:a9fe:a9:fe00:: — RFC 8215 Local-Use NAT64 wrapping 169.254.169.254
/// (cloud IMDS). RFC 6052 §2.2 /48 embedding: octets in segs[3] and
/// segs[4].lo/segs[5].hi, u-octet (segs[4].hi) reserved-zero.
fn nat64_lup(a: u8, b: u8, c: u8, d: u8) -> Ipv6Addr {
    let s3 = ((a as u16) << 8) | b as u16;
    let s4 = c as u16; // u-octet (hi byte) zero
    let s5 = (d as u16) << 8;
    Ipv6Addr::new(0x0064, 0xff9b, 0x0001, s3, s4, s5, 0, 0)
}

#[test]
fn nat64_local_use_prefix_wrapping_imds_is_bogon() {
    let addr = nat64_lup(169, 254, 169, 254);
    assert_eq!(
        addr,
        "64:ff9b:1:a9fe:a9:fe00::".parse::<Ipv6Addr>().unwrap(),
        "LUP embedding must produce the documented literal"
    );
    // Pre-fix: bogon.rs only decomposed the /96 well-known prefix, so this /48
    // Local-Use form fell through to the generic IPv6 checks and returned false.
    assert!(
        TestApi.ip_addr_is_bogon(IpAddr::V6(addr)),
        "NAT64 Local-Use 64:ff9b:1::/48 wrapping IMDS 169.254.169.254 must be a bogon"
    );
    // Same verdict through the verifier's URL gate.
    assert!(
        is_private_url("http://[64:ff9b:1:a9fe:a9:fe00::]/latest/meta-data/"),
        "SSRF URL gate must block NAT64 Local-Use-wrapped cloud metadata"
    );
}

#[test]
fn nat64_local_use_prefix_wrapping_rfc1918_and_loopback_is_bogon() {
    assert!(
        TestApi.ip_addr_is_bogon(IpAddr::V6(nat64_lup(10, 0, 0, 1))),
        "NAT64 Local-Use wrapping 10.0.0.1 (RFC1918) must be a bogon"
    );
    assert!(
        TestApi.ip_addr_is_bogon(IpAddr::V6(nat64_lup(127, 0, 0, 1))),
        "NAT64 Local-Use wrapping 127.0.0.1 (loopback) must be a bogon"
    );
}

#[test]
fn nat64_local_use_prefix_nonzero_u_octet_still_decomposes_internal_v4() {
    // Adversarial: RFC 6052 reserves the u-octet (bits 64-71) as zero, but the
    // whole /48 is NAT64. An attacker setting u=0xff must NOT smuggle an
    // embedded internal IPv4 past the screen — we decompose regardless of u.
    let mut addr = nat64_lup(169, 254, 169, 254);
    let mut segs = addr.segments();
    segs[4] |= 0xff00; // set the reserved u-octet
    addr = Ipv6Addr::from(segs);
    assert_ne!(
        addr,
        nat64_lup(169, 254, 169, 254),
        "u-octet must actually differ for this to be adversarial"
    );
    assert!(
        TestApi.ip_addr_is_bogon(IpAddr::V6(addr)),
        "nonzero-u NAT64 Local-Use wrapping IMDS must still be blocked (fail closed)"
    );
}

#[test]
fn nat64_local_use_prefix_wrapping_public_ipv4_is_allowed() {
    // Negative twin: 64:ff9b:1:808:8:800:: == LUP wrapping 8.8.8.8 (public).
    // Over-blocking a globally routable embedded IPv4 would be a false positive
    // that silently kills real verification.
    let addr = nat64_lup(8, 8, 8, 8);
    assert_eq!(addr, "64:ff9b:1:808:8:800::".parse::<Ipv6Addr>().unwrap());
    assert!(
        !TestApi.ip_addr_is_bogon(IpAddr::V6(addr)),
        "NAT64 Local-Use wrapping public 8.8.8.8 must be allowed"
    );
    assert!(
        !is_private_url("http://[64:ff9b:1:808:8:800::]/"),
        "SSRF URL gate must allow NAT64 Local-Use-wrapped public IPv4"
    );
}

#[test]
fn nat64_well_known_prefix_still_decomposes_after_refactor() {
    // Regression: the /96 well-known prefix path must survive the dedup into
    // `nat64_embedded_ipv4`. 64:ff9b::a9fe:a9fe == WKP wrapping 169.254.169.254.
    let wkp = "64:ff9b::a9fe:a9fe".parse::<Ipv6Addr>().unwrap();
    assert!(
        TestApi.ip_addr_is_bogon(IpAddr::V6(wkp)),
        "NAT64 well-known-prefix-wrapped IMDS must remain a bogon"
    );
    let wkp_public = "64:ff9b::808:808".parse::<Ipv6Addr>().unwrap();
    assert!(
        !TestApi.ip_addr_is_bogon(IpAddr::V6(wkp_public)),
        "NAT64 well-known-prefix-wrapped public IPv4 must remain allowed"
    );
}

#[test]
fn nat64_prefix_boundary_not_over_matched() {
    // 64:ff9b:2:: is neither the /96 WKP nor the /48 LUP (segs[2]==2). With
    // trailing zero segments it embeds 0.0.0.0 under neither rule; the generic
    // checks decide. It must NOT be treated as a LUP wrapper of some bogon.
    let neighbor = Ipv6Addr::new(0x0064, 0xff9b, 0x0002, 0x0808, 0x0008, 0x0800, 0, 0);
    // segs[2]==2 → not LUP; a public embedded 8.8.8.8 would be over-blocked if
    // the matcher wrongly accepted segs[2]!=1.
    assert!(
        !TestApi.ip_addr_is_bogon(IpAddr::V6(neighbor)),
        "64:ff9b:2::/48 is not a standardized NAT64 prefix; must not be decomposed"
    );
}

// ===========================================================================
// 2. Proxy client screens resolved IPs (proxy-SSRF fix)
// ===========================================================================

fn sock(s: &str) -> SocketAddr {
    s.parse().expect("valid socket addr literal")
}

#[test]
fn proxy_client_rejects_rebinding_host_resolving_to_loopback() {
    // Adversarial: a collector host that passes the string check but resolves to
    // 127.0.0.1. Pre-fix, `proxy_in_use == true` returned the proxy client
    // BEFORE any DNS screen, so the register/poll/deregister secret flowed to
    // loopback. The screen must now run on the proxied path too.
    let err = TestApi
        .oob_collector_reuses_proxy_client(
            "https://collector.example",
            true,
            Ok(vec![sock("127.0.0.1:443")]),
        )
        .expect_err("proxy path must screen a host resolving to loopback");
    assert_eq!(
        redact_interactsh_error(&err),
        "interactsh collector host blocked by SSRF guard: \
         https://collector.example resolves to a private/loopback/link-local address"
    );
}

#[test]
fn proxy_client_rejects_rebinding_host_resolving_to_nat64_internal() {
    // The NAT64 LUP fix and the proxy screen compose: a host resolving to a
    // NAT64-Local-Use-wrapped IMDS address is rejected on the proxied path.
    let internal = SocketAddr::new(IpAddr::V6(nat64_lup(169, 254, 169, 254)), 443);
    let err = TestApi
        .oob_collector_reuses_proxy_client("https://collector.example", true, Ok(vec![internal]))
        .expect_err("proxy path must reject NAT64-wrapped internal resolve");
    assert!(
        redact_interactsh_error(&err).contains("private/loopback/link-local address"),
        "NAT64-wrapped internal resolve must be screened on the proxy path"
    );
}

#[test]
fn proxy_client_reused_for_public_resolve() {
    // Positive twin: a public resolve under a proxy keeps the caller's proxy
    // client (Ok(true) = reuse proxy) — the screen must not over-block.
    let reuses_proxy = TestApi
        .oob_collector_reuses_proxy_client(
            "https://collector.example",
            true,
            Ok(vec![sock("8.8.8.8:443")]),
        )
        .expect("public resolve under proxy must pass the screen");
    assert!(
        reuses_proxy,
        "proxied path must reuse the caller's proxy client after a clean screen"
    );
}

#[test]
fn direct_client_pins_for_public_resolve() {
    // Direct path (no proxy) with a public resolve pins a fresh client
    // (Ok(false) = not proxy reuse).
    let reuses_proxy = TestApi
        .oob_collector_reuses_proxy_client(
            "https://collector.example",
            false,
            Ok(vec![sock("8.8.8.8:443")]),
        )
        .expect("public resolve direct must pass the screen");
    assert!(
        !reuses_proxy,
        "direct path must pin a fresh DNS-pinned client, not reuse a proxy client"
    );
}

#[test]
fn direct_client_still_rejects_private_resolve() {
    // Regression: the direct path's screen is unchanged by the refactor.
    let err = TestApi
        .oob_collector_reuses_proxy_client(
            "https://collector.example",
            false,
            Ok(vec![sock("169.254.169.254:443")]),
        )
        .expect_err("direct path must reject an IMDS resolve");
    assert!(redact_interactsh_error(&err).contains("private/loopback/link-local address"));
}

#[test]
fn proxy_and_direct_both_reject_dns_failure_before_contact() {
    // A DNS failure must fail closed on BOTH paths (no silent proxy fallthrough).
    for proxy in [true, false] {
        let err = TestApi
            .oob_collector_reuses_proxy_client(
                "https://collector.example",
                proxy,
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "synthetic dns timeout",
                )),
            )
            .expect_err("DNS failure must fail closed regardless of proxy");
        let display = redact_interactsh_error(&err);
        assert!(
            display.contains("DNS resolution failed before SSRF screening")
                && display.contains("collector was not contacted"),
            "proxy={proxy}: DNS failure must block loudly before contact, got {display}"
        );
    }
}

// ===========================================================================
// 3. normalize_server keeps scheme/host/port only (observable via mint host)
// ===========================================================================

/// Mint a callback host from a raw collector string through the real
/// `for_test` → `normalize_server` → `server_host` → `mint_url` path.
fn minted_host(server: &str) -> String {
    let client = TestApi
        .interactsh_client_for_test(server)
        .expect("for_test RSA keygen must succeed");
    TestApi.interactsh_client_mint_url(&client).host
}

#[test]
fn normalize_strips_bare_path_component() {
    // Adversarial: `oast.fun/evil` pre-fix survived as host `oast.fun/evil`,
    // minting the malformed `<id>.oast.fun/evil`.
    let host = minted_host("oast.fun/evil/path");
    assert!(
        host.ends_with(".oast.fun"),
        "path must be dropped, leaving .oast.fun, got {host}"
    );
    assert!(
        !host.contains('/') && !host.contains("evil"),
        "no path component may leak into the callback host, got {host}"
    );
}

#[test]
fn normalize_strips_path_from_full_url() {
    let host = minted_host("https://oast.fun/latest/meta-data");
    assert!(host.ends_with(".oast.fun"), "got {host}");
    assert!(
        !host.contains('/') && !host.contains("meta-data"),
        "full-URL path must not leak into the callback host, got {host}"
    );
}

#[test]
fn normalize_preserves_explicit_port() {
    // "keep scheme/host/port only" — a non-default port is kept, path dropped.
    let host = minted_host("https://oast.fun:8443/evil");
    assert!(
        host.ends_with(".oast.fun:8443"),
        "explicit port must be preserved, got {host}"
    );
    assert!(!host.contains("/evil"), "path must be dropped, got {host}");
}

#[test]
fn normalize_drops_userinfo_and_reveals_true_host() {
    // Adversarial: `oast.fun@internal` — a naive "keep the left side" would
    // trust oast.fun, but `internal` is the real connect target. Parsing to
    // scheme/host/port reveals it (and downstream `is_private_url` then blocks
    // the dotless `internal`).
    let host = minted_host("oast.fun@internal");
    assert!(
        !host.contains("oast.fun") && !host.contains('@'),
        "userinfo must not be mistaken for the host, got {host}"
    );
    assert!(
        host.ends_with(".internal"),
        "the true host `internal` must be surfaced, got {host}"
    );
    // And the collector policy blocks that revealed host string-side.
    assert!(
        is_private_url("https://internal"),
        "dotless internal host must be SSRF-blocked"
    );
}

#[test]
fn normalize_still_force_upgrades_http_and_strips_trailing_slash() {
    // Regression: existing contract preserved. http:// → https://, trailing / gone.
    let host = minted_host("http://example.test/");
    assert!(host.ends_with(".example.test"), "got {host}");
    assert!(
        !host.contains('/') && !host.contains("http://"),
        "got {host}"
    );
}

// ===========================================================================
// 4. rate_limit low-uptime slot init does not panic (checked_sub)
// ===========================================================================

#[test]
fn rate_limit_initial_slot_does_not_underflow_on_low_uptime() {
    // Adversarial: on a fresh container `Instant::now()` is < interval from the
    // monotonic origin, so `now - interval` PANICS. We model that by asking for
    // an interval far larger than any real uptime; `checked_sub` clamps to now.
    let now = Instant::now();
    let clamped = TestApi.rate_limiter_initial_last_request(now, Duration::from_secs(u64::MAX));
    assert_eq!(
        clamped, now,
        "an unrepresentable back-step must clamp to now, never panic"
    );
}

#[test]
fn rate_limit_initial_slot_steps_back_one_interval_when_representable() {
    // Positive twin: with a representable interval the slot starts exactly one
    // interval in the past so the first request is admitted immediately.
    let now = Instant::now();
    let interval = Duration::from_secs(1);
    let back = TestApi.rate_limiter_initial_last_request(now, interval);
    assert!(back < now, "representable interval must step strictly back");
    assert_eq!(
        now.duration_since(back),
        interval,
        "the step-back must equal exactly one interval"
    );
}

#[test]
fn rate_limit_source_uses_checked_sub_not_panicking_subtraction() {
    // Source guard: the panicking `Instant::now() - default` form must not
    // return to the hot path; the slot init must go through `initial_last_request`.
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/rate_limit.rs"))
        .expect("rate_limit.rs must be readable");
    assert!(
        src.contains("initial_last_request(Instant::now(), default)"),
        "wait() must seed the slot via initial_last_request"
    );
    assert!(
        src.contains("checked_sub"),
        "initial_last_request must use checked_sub"
    );
    assert!(
        !src.contains("Instant::now() - default"),
        "the panicking Instant::now() - default form must be gone"
    );
}
