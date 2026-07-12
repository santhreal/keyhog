//! WebSource SSRF unification lock. The WebSource IP screen once shipped a
//! hand-rolled subset (`is_loopback || is_private || is_link_local || …`) that
//! silently let a whole class of addresses through — CGN (100.64.0.0/10), IETF
//! benchmark (198.18.0.0/15), IETF protocol assignment (192.0.0.0/24), Class E
//! (240.0.0.0/4), and the non-zero 0.0.0.0/8 space — an SSRF pivot into
//! internal / provider space. The fork was removed: `is_disallowed_web_host`
//! now delegates to `keyhog_verifier::ssrf::is_private_url` and
//! `is_disallowed_ip` to `is_private_ip_addr` (the single fleet-canonical
//! predicate; see `crates/sources/src/web/ssrf.rs`).
//!
//! This test locks that unification behaviourally: every range the old fork
//! missed must be BLOCKED on BOTH the URL-host screen and the resolved-IP
//! screen, and unambiguously-public addresses must still be allowed (no
//! block-everything degenerate). Re-forking WebSource to a subset would turn
//! this red — before the SSRF pivot could ship.

use keyhog_sources::testing::{SourceTestApi, TestApi};
use std::net::{IpAddr, Ipv4Addr};

/// (label, address) pairs inside the ranges the OLD hand-rolled fork let
/// through. All must be SSRF-blocked by the unified screen. Endpoints of each
/// range are included so an off-by-one re-fork is caught too.
const FORKED_GAP_ADDRS: &[(&str, [u8; 4])] = &[
    ("CGN 100.64.0.0/10 low", [100, 64, 0, 1]),
    ("CGN 100.127/10 high", [100, 127, 255, 254]),
    ("IETF benchmark 198.18.0.0/15 low", [198, 18, 0, 1]),
    ("IETF benchmark 198.19/15 high", [198, 19, 255, 254]),
    ("IETF protocol 192.0.0.0/24", [192, 0, 0, 1]),
    ("Class E 240.0.0.0/4 low", [240, 0, 0, 1]),
    ("Class E 250.1.2.3", [250, 1, 2, 3]),
    ("0.0.0.0/8 non-zero 0.1.2.3", [0, 1, 2, 3]),
];

/// Unambiguously-public addresses — the screen must NOT block these (guard
/// against a degenerate block-everything screen).
const PUBLIC_ADDRS: &[[u8; 4]] = &[[8, 8, 8, 8], [1, 1, 1, 1], [93, 184, 216, 34]];

fn v4(o: [u8; 4]) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3]))
}

#[cfg(feature = "web")]
#[test]
fn websource_ssrf_screen_blocks_historically_forked_ranges() {
    for &(label, o) in FORKED_GAP_ADDRS {
        let ip = v4(o);
        assert!(
            TestApi.is_disallowed_ip(ip),
            "resolved-IP SSRF screen must block {label} ({ip}) — the old-fork gap"
        );
        let url = format!("http://{ip}/x.js");
        assert!(
            TestApi.is_disallowed_web_host(&url),
            "URL-host SSRF screen must block {label} ({url}) — the old-fork gap"
        );
    }

    for &o in PUBLIC_ADDRS {
        let ip = v4(o);
        assert!(
            !TestApi.is_disallowed_ip(ip),
            "public {ip} must NOT be SSRF-blocked (screen is not a blanket deny)"
        );
        assert!(
            !TestApi.is_disallowed_web_host(&format!("http://{ip}/x.js")),
            "public {ip} URL must NOT be SSRF-blocked"
        );
    }
}

#[cfg(not(feature = "web"))]
#[test]
fn websource_ssrf_screen_blocks_historically_forked_ranges() {}
