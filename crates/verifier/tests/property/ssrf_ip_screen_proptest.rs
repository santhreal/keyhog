//! Property / differential coverage for the SSRF IP-address screen — the
//! security-critical gate (`keyhog_verifier::ssrf`) that stops live credential
//! verification from being used as an SSRF proxy against internal services.
//!
//! Fixed-vector coverage lives in `regression_ssrf_screen_matrix` and
//! `regression_ssrf_short_form_ip`; this file asserts the INVARIANTS across a
//! large sample of the IPv4/IPv6 address space and of adversarial URL strings.
//!
//! Dependency-free by design: a fixed-seed LCG (Numerical Recipes constants)
//! drives the "random" sampling, so the sample — and therefore any failing
//! case — is byte-for-byte reproducible on every run without pulling in a
//! `proptest` dev-dependency. Every assertion pins the exact boolean the screen
//! must return, never a shape/`!is_empty` check.

use crate::common::lcg;
use keyhog_verifier::ssrf::{is_private_ip_addr, is_private_ip_addr_fast, is_private_url};
use keyhog_verifier::testing::{TestApi, VerifierTestApi};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Samples per differential sweep. Large enough to cover the reserved-range
/// boundaries densely; the screen is a handful of integer comparisons, so even
/// hundreds of thousands of calls finish in well under a second.
const SAMPLES: usize = 100_000;

#[test]
fn fast_and_full_ipv4_screen_never_diverge() {
    // The verifier keeps two entry points (`_fast` historical alias + the
    // authoritative `is_private_ip_addr`). A divergence where one says "public"
    // and the other says "private" is a DIRECT SSRF gap: the fast path could let
    // a target through that the full path would refuse. They must agree on every
    // address. This locks that invariant against a future "optimization" of the
    // fast path that reintroduces a partial (pre-bogon) subset.
    let mut state = 0x1234_5678;
    for _ in 0..SAMPLES {
        let ip = IpAddr::V4(Ipv4Addr::from(lcg(&mut state)));
        assert_eq!(
            is_private_ip_addr_fast(&ip),
            is_private_ip_addr(&ip),
            "fast/full SSRF screen diverged on {ip} — a divergence is an SSRF gap"
        );
    }
}

#[test]
fn fast_and_full_ipv6_screen_never_diverge() {
    let mut state = 0x9E37_79B9;
    for _ in 0..SAMPLES {
        let mut seg = [0u16; 8];
        for s in &mut seg {
            *s = (lcg(&mut state) & 0xFFFF) as u16;
        }
        let ip = IpAddr::V6(Ipv6Addr::new(
            seg[0], seg[1], seg[2], seg[3], seg[4], seg[5], seg[6], seg[7],
        ));
        assert_eq!(
            is_private_ip_addr_fast(&ip),
            is_private_ip_addr(&ip),
            "fast/full SSRF screen diverged on {ip} — a divergence is an SSRF gap"
        );
    }
}

#[test]
fn all_dangerous_ipv4_ranges_are_blocked() {
    // Every address in these IANA special-use ranges is a private/loopback/
    // link-local/multicast/reserved target the verifier must refuse. Each range
    // is walked densely (both exact endpoints plus ~5000 interior hosts) so an
    // off-by-one hole at a range boundary is caught.
    let ranges: &[(Ipv4Addr, Ipv4Addr, &str)] = &[
        (
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 255, 255, 255),
            "10/8 private",
        ),
        (
            Ipv4Addr::new(172, 16, 0, 0),
            Ipv4Addr::new(172, 31, 255, 255),
            "172.16/12 private",
        ),
        (
            Ipv4Addr::new(192, 168, 0, 0),
            Ipv4Addr::new(192, 168, 255, 255),
            "192.168/16 private",
        ),
        (
            Ipv4Addr::new(127, 0, 0, 0),
            Ipv4Addr::new(127, 255, 255, 255),
            "127/8 loopback",
        ),
        (
            Ipv4Addr::new(169, 254, 0, 0),
            Ipv4Addr::new(169, 254, 255, 255),
            "169.254/16 link-local",
        ),
        (
            Ipv4Addr::new(224, 0, 0, 0),
            Ipv4Addr::new(239, 255, 255, 255),
            "224/4 multicast",
        ),
        (
            Ipv4Addr::new(240, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
            "240/4 class-E reserved",
        ),
    ];
    for (start, end, label) in ranges {
        let (s, e) = (u32::from(*start) as u64, u32::from(*end) as u64);
        let stride = ((e - s) / 5000).max(1);
        let mut a = s;
        while a <= e {
            let ip = IpAddr::V4(Ipv4Addr::from(a as u32));
            assert!(
                is_private_ip_addr(&ip),
                "{label}: {ip} must be SSRF-blocked"
            );
            a += stride;
        }
        assert!(
            is_private_ip_addr(&IpAddr::V4(*start)),
            "{label}: start {start} must block"
        );
        assert!(
            is_private_ip_addr(&IpAddr::V4(*end)),
            "{label}: end {end} must block"
        );
    }
}

#[test]
fn well_known_public_ipv4_is_not_blocked() {
    // Guard against the degenerate "block everything" screen: a screen that
    // refuses all addresses would pass every block-test above while making live
    // verification useless. Unambiguously-public addresses MUST pass.
    for ip in [
        Ipv4Addr::new(8, 8, 8, 8),        // Google public DNS
        Ipv4Addr::new(8, 8, 4, 4),        // Google public DNS
        Ipv4Addr::new(93, 184, 216, 34),  // example.com
        Ipv4Addr::new(208, 67, 222, 222), // OpenDNS
    ] {
        assert!(
            !is_private_ip_addr(&IpAddr::V4(ip)),
            "{ip} is a public address — the SSRF screen must NOT block it"
        );
        assert!(
            !is_private_url(&format!("http://{ip}/")),
            "public {ip} URL must not be SSRF-blocked"
        );
    }
}

#[test]
fn integer_hex_and_octal_encoded_private_ipv4_is_blocked_via_url() {
    // A permissive resolver (glibc/musl getaddrinfo) canonicalizes decimal, hex
    // and octal integer hosts into an IPv4. The SSRF screen must block a private
    // target in EVERY encoding — the VRF-001 class of bypass. Every form below
    // resolves to the same private address and must be refused.
    let private = [
        Ipv4Addr::new(127, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(169, 254, 169, 254), // cloud metadata endpoint
        Ipv4Addr::new(172, 16, 0, 1),
    ];
    for ip in private {
        let n = u32::from(ip);
        let forms = [
            format!("http://{ip}/"),    // dotted quad
            format!("http://{n}/"),     // bare decimal integer
            format!("http://0x{n:x}/"), // hex integer
            format!("http://0{n:o}/"),  // octal integer
        ];
        for url in &forms {
            assert!(
                is_private_url(url),
                "SSRF bypass: {url} resolves to private {ip} and must be blocked"
            );
        }
    }
}

#[test]
fn inet_aton_short_form_private_ipv4_is_blocked_via_url() {
    // getaddrinfo/`inet_aton` accept abbreviated dotted forms that pack the
    // trailing bytes into the final field: `127.1` → 127.0.0.1, `172.16.1` →
    // 172.16.0.1, plus hex/octal-leading fields (`0x7f.1`). These dot-bearing
    // short forms bypass the dotless-domain refusal, so the screen's
    // `canonicalize_short_form_ipv4` must resolve and block each one — this is
    // the class the source calls out as an SSRF bypass (a 2-/3-part hex-leading
    // short form reaching neither the dotless gate nor `looks_like_malformed_ip`).
    let private = [
        Ipv4Addr::new(127, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(172, 16, 0, 1),
    ];
    for ip in private {
        let o = ip.octets();
        let (a, b, c, d) = (o[0] as u32, o[1] as u32, o[2] as u32, o[3] as u32);
        let two_part = format!("http://{a}.{}/", (b << 16) | (c << 8) | d);
        let three_part = format!("http://{a}.{b}.{}/", (c << 8) | d);
        let hex_two = format!("http://0x{a:x}.{}/", (b << 16) | (c << 8) | d);
        for url in [&two_part, &three_part, &hex_two] {
            assert!(
                is_private_url(url),
                "SSRF bypass: short-form {url} resolves to private {ip} and must be blocked"
            );
        }
    }
}

#[test]
fn is_private_url_never_panics_and_fails_closed_on_adversarial_input() {
    // The screen must ALWAYS return a bool (fail-closed on anything it cannot
    // parse), never panic — a panic in the SSRF gate would abort verification or
    // could be turned into a DoS. Sweep pseudo-random printable-ASCII strings
    // plus a curated set of known-nasty inputs.
    let mut state = 0xDEAD_BEEF;
    for _ in 0..20_000 {
        let len = (lcg(&mut state) % 40) as usize;
        let mut s = String::with_capacity(len);
        for _ in 0..len {
            let c = (lcg(&mut state) % 95) as u8 + 32; // printable ASCII 32..=126
            s.push(c as char);
        }
        let _ = is_private_url(&s);
    }
    for s in [
        "",
        "http://",
        "http://[",
        "http://0x",
        "http://.",
        "http://999.999.999.999",
        "http://0x7f.1",
        "http://127.1",
        "http://172.16.1",
        "ftp://127.0.0.1",
        "file:///etc/passwd",
        "http://2130706433",
        "http://①②③④",
        "http://127.0.0.1:99999999999999999999",
        "http://[::1]",
        "http://[fe80::1]",
        "gopher://127.0.0.1:70",
    ] {
        // Must return, never panic; unparseable/non-http(s) forms fail closed.
        let _ = is_private_url(s);
    }
    // Two concrete fail-closed pins: a non-http(s) scheme to a private target
    // and an unparseable URL are both refused.
    assert!(
        is_private_url("ftp://127.0.0.1"),
        "non-http(s) scheme must fail closed"
    );
    assert!(
        is_private_url("not a url at all"),
        "unparseable URL must fail closed"
    );
}

/// Structured IPv6 families a uniform random sweep almost never hits, but which
/// carry the security-critical bogon decompositions (IPv4-mapped, NAT64,
/// site-local, loopback/unspecified). Asserted explicitly so the parity and
/// bogon-superset guards cover them, not just by chance.
fn structured_v6_probe() -> [IpAddr; 8] {
    let v6 = |a, b, c, d, e, f, g, h| IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h));
    [
        v6(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001), // ::ffff:127.0.0.1 (mapped loopback)
        v6(0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001), // ::ffff:10.0.0.1  (mapped RFC1918)
        v6(0, 0, 0, 0, 0, 0xffff, 0x0808, 0x0808), // ::ffff:8.8.8.8   (mapped public)
        v6(0xfec0, 0, 0, 0, 0, 0, 0, 1),           // fec0::1          (site-local)
        v6(0x0064, 0xff9b, 0, 0, 0, 0, 0x0a00, 0x0001), // 64:ff9b::10.0.0.1 (NAT64 private)
        v6(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111), // Cloudflare (public global-unicast)
        v6(0, 0, 0, 0, 0, 0, 0, 1),                // ::1             (loopback)
        v6(0, 0, 0, 0, 0, 0, 0, 0),                // ::              (unspecified)
    ]
}

#[test]
fn every_bogon_is_ssrf_blocked() {
    // The SSRF screen is a strict SUPERSET of the fleet-wide bogon predicate:
    // every address `ip_addr_is_bogon` rejects must ALSO be SSRF-blocked (the
    // screen additionally blocks v4 multicast / class-E reserved on top). If a
    // bogon ever slipped past the screen it would be a live SSRF hole. This ties
    // the two predicates together so a future edit to either cannot open a gap
    // between them. Swept over v4 + v6 + the structured v6 families, against the
    // REAL bogon predicate (not a re-implementation — ONE source of truth).
    let mut state = 0x0B06_0002;
    let mut bogons_seen = 0usize;
    for _ in 0..SAMPLES {
        let v4 = IpAddr::V4(Ipv4Addr::from(lcg(&mut state)));
        if TestApi.ip_addr_is_bogon(v4) {
            bogons_seen += 1;
            assert!(is_private_ip_addr(&v4), "bogon not SSRF-blocked: {v4}");
        }
        let mut seg = [0u16; 8];
        for s in &mut seg {
            *s = (lcg(&mut state) & 0xFFFF) as u16;
        }
        let v6 = IpAddr::V6(Ipv6Addr::new(
            seg[0], seg[1], seg[2], seg[3], seg[4], seg[5], seg[6], seg[7],
        ));
        if TestApi.ip_addr_is_bogon(v6) {
            bogons_seen += 1;
            assert!(is_private_ip_addr(&v6), "bogon not SSRF-blocked: {v6}");
        }
    }
    for ip in structured_v6_probe() {
        // Fast/full parity across the structured families too — uniform random
        // sampling almost never lands on a mapped-v4 / NAT64 / site-local shape.
        assert_eq!(
            is_private_ip_addr_fast(&ip),
            is_private_ip_addr(&ip),
            "fast/full SSRF screen diverged on {ip}"
        );
        if TestApi.ip_addr_is_bogon(ip) {
            bogons_seen += 1;
            assert!(is_private_ip_addr(&ip), "bogon not SSRF-blocked: {ip}");
        }
    }
    // Sanity: the v4 bogon space (RFC1918/loopback/link-local/…) is large, so a
    // 100k v4 sweep hits it thousands of times. A zero would mean the implication
    // was never exercised — the guard would prove nothing.
    assert!(
        bogons_seen > 100,
        "sweep never hit a bogon ({bogons_seen}) — the implication was never exercised"
    );
    // The screen is a STRICT superset: v4 multicast + class-E reserved are
    // SSRF-blocked even though they are NOT classic bogons — the "extra" the
    // screen adds on top of the bogon set.
    let mcast = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1));
    let class_e = IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1));
    assert!(
        is_private_ip_addr(&mcast),
        "224.0.0.1 multicast must be SSRF-blocked"
    );
    assert!(
        is_private_ip_addr(&class_e),
        "240.0.0.1 class-E must be SSRF-blocked"
    );
    assert!(
        !TestApi.ip_addr_is_bogon(mcast),
        "224.0.0.1 is the screen's superset extra, not a classic bogon"
    );
}

#[test]
fn url_ip_literal_matches_ip_screen_across_address_space() {
    // For an IP-literal URL host, `is_private_url` must decide EXACTLY as the
    // direct IP screen — no gap (a private target let through) and no over-block
    // (a public target refused). Stronger than the public/private split checks
    // above: asserts exact equality across the whole sampled v4 space, so a
    // divergence on any interior address is caught.
    let mut state = 0x00C0_FFEE;
    for _ in 0..SAMPLES {
        let v4 = Ipv4Addr::from(lcg(&mut state));
        let url = format!("http://{v4}/");
        assert_eq!(
            is_private_url(&url),
            is_private_ip_addr(&IpAddr::V4(v4)),
            "url/ip SSRF screen disagreed on {v4}"
        );
    }
}
