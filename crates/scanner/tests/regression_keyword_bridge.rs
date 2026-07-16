//! Regression: the generic credential keyword-bridge identity and its narrow
//! reach.
//!
//! The generic assignment bridge (`engine/phase2_generic.rs`
//! `scan_generic_assignments` -> `build_synthetic_raw_match`) is the ONLY path
//! that turns an un-vendored `<credential-keyword>=<value>` line into a finding.
//! It is deliberately narrow: it fires only on lines that carry a generic
//! credential-assignment keyword (the prefilter vocab derived from the generic
//! detector specs), stamps every emit with the single stable
//! identity owned by the active generic detector TOML (`generic-password`,
//! `generic-keyword-secret`, `generic-api-key`, or `generic-secret`) / service
//! `generic` / `Severity::Medium`, and applies a value-shape + entropy gauntlet
//! before emitting. Overlapping keywords intentionally retain detector-local
//! ownership: `password=` may have both the native password detector and the
//! low-entropy keyword detector, while `private_key=` is owned by the keyword
//! detector. Because the trigger set is a fixed credential vocabulary (not "any
//! assignment"), the bridge reaches only a small slice of a source tree's
//! assignments, a random `hostname=<token>` or a bare high-entropy blob never
//! reaches it. This file pins:
//!   * detector-local ownership for a bridged `password=<value>` (positive),
//!   * that the whole credential vocabulary + all three separator spellings
//!     reach an active generic owner (breadth),
//!   * the low-entropy floor and 8-byte length floor reject trivial values
//!     (negative / boundary),
//!   * the SAME value surfaces under a credential key yet NOT under a
//!     non-credential key, the load-bearing "narrow surface" contract, and
//!   * the bridge is produced on the host-independent scalar `CpuFallback`
//!     path (it is a scalar keyword+regex path, never accelerator-gated).
//!
//! HOST-INDEPENDENCE: every scan runs on `ScanBackend::CpuFallback`, so no
//! assertion here depends on Hyperscan/SIMD/GPU being present. The generic
//! bridge is a scalar detector and its identity is the same on every host.
//!
//! Entropy math is taken from the crate's own
//! `testing::entropy_fast::shannon_entropy_simd`: the SAME function the engine
//! feeds the floor gate, so a "reason is entropy, not shape" claim is proven
//! against the number the gate actually saw (no epsilon slop between the test's
//! math and the engine's).

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata, DetectorKind, RawMatch, Severity};
use keyhog_scanner::testing::entropy_fast::shannon_entropy_simd;
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};

/// Generic detector IDs are data-owned in the detector corpus. This test keeps
/// the accepted family explicit so a new generic owner cannot silently pass by
/// merely sharing the `generic-` prefix.
const GENERIC_DETECTOR_IDS: &[&str] = &[
    "generic-api-key",
    "generic-keyword-secret",
    "generic-password",
    "generic-secret",
];

/// `generic-keyword-secret` detector-local floor: a
/// keyword-anchored value at or below this bits/byte is dropped even with the
/// low-entropy floor ON (the shipped default). Used here only to prove that a
/// rejected fixture's rejection reason is/ isn't the entropy floor.
const KEYWORD_SECRET_FLOOR: f64 = 1.5;

/// A 16-byte value with Shannon entropy exactly 3.5 bits/byte: clears BOTH the
/// keyword (1.5) and the strict generic-secret (2.8) floors, so it surfaces
/// under any credential keyword regardless of the low-entropy toggle. The
/// entropy value is pinned by `high_entropy_fixture_entropy_is_exactly_3_5`.
const HIGH_ENTROPY_VALUE: &str = "ufnlbbavawsdeecn";

/// An 8-byte value with Shannon entropy exactly 2.5 bits/byte: inside the
/// `[1.5, 2.8)` band, i.e. above the keyword floor but below the strict generic
/// floor. Surfaces with the shipped default (keyword floor ON) yet is far too
/// low to trip any isolated bare-entropy path, the ideal probe for the
/// "non-credential key does not bridge" negative twin.
const MID_ENTROPY_VALUE: &str = "gjbubxsu";

/// Compile the full shipped detector set. `min_confidence` is pinned to 0.0 so
/// the confidence gate never confounds a bridge-identity or floor assertion; the
/// low-entropy keyword floor stays at its shipped default (ON).
fn default_scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let mut cfg = ScannerConfig::default();
    cfg.min_confidence = 0.0;
    assert!(
        cfg.generic_keyword_low_entropy,
        "shipped default keeps the keyword low-entropy floor ON"
    );
    CompiledScanner::compile(detectors)
        .expect("compile scanner")
        .with_config(cfg)
}

fn scanner_with_generic_max_len(max_len: usize) -> CompiledScanner {
    let mut detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    for detector in &mut detectors {
        if detector.kind == DetectorKind::Phase2Generic {
            detector.max_len = Some(max_len);
        }
    }
    let mut cfg = ScannerConfig::default();
    cfg.min_confidence = 0.0;
    CompiledScanner::compile(detectors)
        .expect("compile scanner with detector-owned maximum")
        .with_config(cfg)
}

/// Scan a single filesystem chunk on the host-independent scalar CpuFallback
/// backend and collect every raw match.
fn scan(scanner: &CompiledScanner, body: &str) -> Vec<RawMatch> {
    let chunk = Chunk {
        data: body.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("/repo/config/service.env".into()),
            ..Default::default()
        },
    };
    scanner.clear_fragment_cache();
    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .into_iter()
        .flatten()
        .collect()
}

fn find<'a>(matches: &'a [RawMatch], credential: &str) -> Option<&'a RawMatch> {
    matches.iter().find(|m| m.credential.as_ref() == credential)
}

/// A generic-bridge finding is one carrying an active generic detector identity
/// for `value`. The exact owner is asserted where ownership is load-bearing.
fn bridged(matches: &[RawMatch], credential: &str) -> bool {
    matches.iter().any(|m| {
        m.credential.as_ref() == credential
            && GENERIC_DETECTOR_IDS.contains(&m.detector_id.as_ref())
    })
}

fn owned_by(matches: &[RawMatch], credential: &str, detector_id: &str) -> bool {
    matches
        .iter()
        .any(|m| m.credential.as_ref() == credential && m.detector_id.as_ref() == detector_id)
}

// ---------------------------------------------------------------------------
// Fixture entropy (pin the numbers the floor gate compares against).
// ---------------------------------------------------------------------------

#[test]
fn high_entropy_fixture_entropy_is_exactly_3_5() {
    // 8 singletons (1/16) + 4 pairs (1/8) over 16 bytes -> -(-2.0 - 1.5) = 3.5.
    let h = shannon_entropy_simd(HIGH_ENTROPY_VALUE.as_bytes());
    assert!(
        (h - 3.5).abs() < 1e-12,
        "{HIGH_ENTROPY_VALUE} entropy must be 3.5 bits/byte, got {h}"
    );
}

#[test]
fn mid_entropy_fixture_entropy_is_exactly_2_5_inside_the_bridge_band() {
    // b:2 u:2 four singletons over 8 bytes -> -(-0.5 - 1.5) = 2.5.
    let h = shannon_entropy_simd(MID_ENTROPY_VALUE.as_bytes());
    assert!(
        (h - 2.5).abs() < 1e-12,
        "{MID_ENTROPY_VALUE} entropy must be 2.5 bits/byte, got {h}"
    );
    assert!(
        h > KEYWORD_SECRET_FLOOR,
        "2.5 must clear the 1.5 keyword floor so it CAN bridge under a credential key"
    );
}

// ---------------------------------------------------------------------------
// Positive: identity of a bridged `password=<value>`.
// ---------------------------------------------------------------------------

#[test]
fn password_assignment_retains_the_detector_local_password_identity() {
    let s = default_scanner();
    let matches = scan(&s, "password=ufnlbbavawsdeecn\n");
    let m = find(&matches, HIGH_ENTROPY_VALUE)
        .unwrap_or_else(|| panic!("password=<value> must bridge; matches: {matches:#?}"));
    assert_eq!(m.detector_id.as_ref(), "generic-password");
    assert_eq!(m.detector_name.as_ref(), "Generic Password");
    assert_eq!(m.service.as_ref(), "generic");
    assert_eq!(m.severity, Severity::Medium);
    assert_eq!(
        m.credential.as_ref(),
        HIGH_ENTROPY_VALUE,
        "the bridged credential is the assignment's right-hand value verbatim"
    );
}

#[test]
fn bridged_match_stamps_the_shannon_entropy_the_floor_gate_saw() {
    let s = default_scanner();
    let matches = scan(&s, "db_password=ufnlbbavawsdeecn\n");
    let m = find(&matches, HIGH_ENTROPY_VALUE)
        .unwrap_or_else(|| panic!("db_password=<value> must bridge; matches: {matches:#?}"));
    let reported = m
        .entropy
        .expect("generic bridge stamps the Shannon entropy");
    let recomputed = shannon_entropy_simd(HIGH_ENTROPY_VALUE.as_bytes());
    assert!(
        (reported - recomputed).abs() < 1e-9,
        "stamped entropy ({reported}) must equal shannon_entropy_simd ({recomputed}), one source of truth"
    );
    assert!(
        (reported - 3.5).abs() < 1e-9,
        "and that shared value is 3.5, got {reported}"
    );
}

#[test]
fn bridged_match_confidence_is_finite_within_unit_interval_and_medium_severity() {
    let s = default_scanner();
    let matches = scan(&s, "api_secret=ufnlbbavawsdeecn\n");
    let m = find(&matches, HIGH_ENTROPY_VALUE)
        .unwrap_or_else(|| panic!("api_secret=<value> must bridge; matches: {matches:#?}"));
    assert_eq!(m.severity, Severity::Medium);
    let conf = m.confidence.expect("bridge finalizes a report confidence");
    assert!(
        conf.is_finite() && conf > 0.0 && conf <= 1.0,
        "bridge confidence must be a finite probability in (0,1], got {conf}"
    );
}

// ---------------------------------------------------------------------------
// Breadth: the credential vocabulary + separator spellings all reach an active
// generic detector owner. This is the surface the bridge is allowed to reach.
// ---------------------------------------------------------------------------

#[test]
fn every_bare_credential_keyword_reaches_an_active_generic_owner() {
    let s = default_scanner();
    // Bare credential slots OWNED by the generic-password keyword set
    // (detectors/generic-password.toml). `pass` and `credential` are NOT in that
    // keyword list, so they intentionally do not bridge and are excluded here.
    let keywords = ["password", "passwd", "pwd", "secret", "token"];
    let mut bridged_count = 0usize;
    for kw in keywords {
        let body = format!("{kw}={HIGH_ENTROPY_VALUE}\n");
        let matches = scan(&s, &body);
        assert!(
            bridged(&matches, HIGH_ENTROPY_VALUE),
            "`{kw}=<value>` must reach an active generic owner; matches: {matches:#?}"
        );
        bridged_count += 1;
    }
    assert_eq!(
        bridged_count,
        keywords.len(),
        "all {} credential keywords must bridge",
        keywords.len()
    );
}

#[test]
fn custom_phase2_corpus_does_not_invent_a_generic_secret_fallback() {
    let mut detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    detectors.retain(|detector| detector.id == "generic-password");
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    config.entropy_enabled = false;
    let scanner = CompiledScanner::compile(detectors)
        .expect("compile explicit generic-password-only corpus")
        .with_config(config);
    let unknown = "Zq8Lm4Np7Rt2Vx9Ks5Hd3Bc6";
    let matches = scan(
        &scanner,
        &format!("password={HIGH_ENTROPY_VALUE}\nunknown_vendor_key={unknown}\n"),
    );

    assert!(
        matches.iter().any(|finding| {
            finding.detector_id.as_ref() == "generic-password"
                && finding.credential.as_ref() == HIGH_ENTROPY_VALUE
        }),
        "the declared generic-password keyword must remain active: {matches:#?}"
    );
    assert!(
        matches
            .iter()
            .all(|finding| finding.credential.as_ref() != unknown),
        "an unowned vendor suffix must not inherit a synthetic generic-secret policy: {matches:#?}"
    );
}

#[test]
fn multiple_vendor_suffix_owners_fail_scanner_construction() {
    let mut detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let password = detectors
        .iter_mut()
        .find(|detector| detector.id == "generic-password")
        .expect("shipped generic-password detector");
    password.generic_vendor_suffix_fallback = true;

    let error = match CompiledScanner::compile(detectors) {
        Ok(_) => panic!("multiple structural vendor owners must not compile"),
        Err(error) => error.to_string(),
    };
    assert!(
        error.contains("multiple detectors declare generic_vendor_suffix_fallback"),
        "construction error must identify the conflicting detector-owned capability: {error}"
    );
}

#[cfg(feature = "ml")]
#[test]
fn detector_ml_policy_controls_generic_assignment_scoring() {
    fn confidence(mode: keyhog_core::DetectorMlMode) -> f64 {
        let mut detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
        detectors.retain(|detector| detector.id == "generic-password");
        detectors[0].ml.match_mode = mode;
        detectors[0].ml.weight = 1.0;
        let mut config = ScannerConfig::default();
        config.min_confidence = 0.0;
        config.entropy_enabled = false;
        let scanner = CompiledScanner::compile(detectors)
            .expect("compile detector-local ML policy")
            .with_config(config);
        let matches = scan(&scanner, &format!("password={HIGH_ENTROPY_VALUE}\n"));
        let finding = matches
            .iter()
            .find(|finding| finding.credential.as_ref() == HIGH_ENTROPY_VALUE)
            .unwrap_or_else(|| {
                panic!("generic password must survive policy comparison: {matches:#?}")
            });
        assert_eq!(finding.detector_id.as_ref(), "generic-password");
        finding.confidence.expect("final confidence")
    }

    let heuristic_only = confidence(keyhog_core::DetectorMlMode::Disabled);
    let model_only = confidence(keyhog_core::DetectorMlMode::Authoritative);
    assert_ne!(
        heuristic_only, model_only,
        "changing only detector.ml.match_mode must alter the shipped scoring path"
    );
}

#[test]
fn all_three_separator_spellings_of_a_compound_keyword_bridge() {
    let s = default_scanner();
    // underscore / hyphen / dot, the three real-world spellings the Tier-B
    // vocabulary ships for every compound key.
    for kw in ["private_key", "private-key", "private.key"] {
        let body = format!("{kw}={HIGH_ENTROPY_VALUE}\n");
        let matches = scan(&s, &body);
        assert!(
            bridged(&matches, HIGH_ENTROPY_VALUE),
            "separator spelling `{kw}=<value>` must bridge; matches: {matches:#?}"
        );
    }
}

#[test]
fn uppercase_keyword_bridges_case_insensitively() {
    // The prefilter and assignment regex fold case; an all-caps key must bridge
    // identically to its lowercase spelling.
    let s = default_scanner();
    let matches = scan(&s, "PASSWORD=gjbubxsu\n");
    let m = find(&matches, MID_ENTROPY_VALUE).unwrap_or_else(|| {
        panic!("PASSWORD=<value> must bridge case-insensitively; matches: {matches:#?}")
    });
    assert!(owned_by(&matches, MID_ENTROPY_VALUE, "generic-password"));
    assert_eq!(m.severity, Severity::Medium);
}

// ---------------------------------------------------------------------------
// Negative: the low-entropy floor rejects trivial values under a real keyword.
// ---------------------------------------------------------------------------

#[test]
fn constant_repeated_char_value_is_rejected_by_the_low_entropy_floor() {
    // Entropy 0.0: a single repeated symbol. Far below the 1.5 keyword floor
    // dropped even though `password=` is a valid credential anchor.
    let value = "aaaaaaaa";
    assert_eq!(
        shannon_entropy_simd(value.as_bytes()),
        0.0,
        "a single repeated byte has zero Shannon entropy"
    );
    let s = default_scanner();
    let matches = scan(&s, "password=aaaaaaaa\n");
    assert!(
        find(&matches, value).is_none(),
        "a zero-entropy value must not bridge; matches: {matches:#?}"
    );
}

#[test]
fn one_bit_alternating_value_is_below_the_keyword_floor_and_rejected() {
    // a:4 b:4 over 8 bytes -> two symbols at 0.5 -> exactly 1.0 bit/byte.
    let value = "abababab";
    let h = shannon_entropy_simd(value.as_bytes());
    assert!(
        (h - 1.0).abs() < 1e-12,
        "abababab entropy must be exactly 1.0 bit/byte, got {h}"
    );
    assert!(
        h < KEYWORD_SECRET_FLOOR,
        "1.0 is below the 1.5 keyword floor, the reason for rejection is entropy"
    );
    let s = default_scanner();
    let matches = scan(&s, "password=abababab\n");
    assert!(
        find(&matches, value).is_none(),
        "a 1.0-bit value must not bridge; matches: {matches:#?}"
    );
}

// ---------------------------------------------------------------------------
// Boundary: the 8-byte length floor. Below 8 the value is rejected as
// `ValueTooShort` BEFORE any identifier gate, even when its entropy clears the
// keyword floor (so the rejection reason is length, not entropy).
// ---------------------------------------------------------------------------

#[test]
fn seven_byte_value_is_rejected_by_the_length_floor_not_entropy() {
    let value = "bcdfghj"; // 7 distinct bytes
    let h = shannon_entropy_simd(value.as_bytes());
    // 7 equiprobable symbols -> log2(7) ~= 2.807355 bits/byte.
    assert!(
        (h - 2.807_355).abs() < 1e-5,
        "bcdfghj entropy must be ~2.807355 bits/byte, got {h}"
    );
    assert!(
        h > KEYWORD_SECRET_FLOOR,
        "its entropy clears the 1.5 keyword floor, so the ONLY reason it can be dropped is the 8-byte length floor"
    );
    let s = default_scanner();
    let matches = scan(&s, "password=bcdfghj\n");
    assert!(
        find(&matches, value).is_none(),
        "a 7-byte value must be rejected by the length floor; matches: {matches:#?}"
    );
}

#[test]
fn eight_byte_value_at_the_length_floor_bridges() {
    // Exactly 8 bytes (`gjbubxsu`), entropy 2.5 clears the keyword floor: the
    // twin of the 7-byte rejection (proving 8 is the inclusive lower bound).
    assert_eq!(MID_ENTROPY_VALUE.len(), 8);
    let s = default_scanner();
    let matches = scan(&s, "password=gjbubxsu\n");
    assert!(
        bridged(&matches, MID_ENTROPY_VALUE),
        "an 8-byte value above the entropy floor must bridge; matches: {matches:#?}"
    );
}

#[test]
fn detector_owned_max_len_accepts_boundary_and_rejects_whole_longer_value() {
    let scanner = scanner_with_generic_max_len(HIGH_ENTROPY_VALUE.len());
    let boundary = scan(&scanner, &format!("app_secret={HIGH_ENTROPY_VALUE}\n"));
    assert!(
        bridged(&boundary, HIGH_ENTROPY_VALUE),
        "max_len is inclusive at the exact detector-owned boundary"
    );

    let over = format!("{HIGH_ENTROPY_VALUE}z");
    let matches = scan(&scanner, &format!("app_secret={over}\n"));
    assert!(
        find(&matches, &over).is_none(),
        "an over-ceiling assignment must be rejected whole, never truncated: {matches:#?}"
    );
}

// ---------------------------------------------------------------------------
// Narrow surface: the bridge fires ONLY on credential-keyword lines. The SAME
// value that bridges under a credential key must NOT surface under an ordinary
// non-credential assignment (the load-bearing "~10% reach" contract).
// ---------------------------------------------------------------------------

#[test]
fn same_value_bridges_under_password_but_not_under_hostname() {
    let s = default_scanner();
    assert!(
        bridged(&scan(&s, "password=gjbubxsu\n"), MID_ENTROPY_VALUE),
        "the value bridges under a credential key"
    );
    let host_matches = scan(&s, "hostname=gjbubxsu\n");
    assert!(
        find(&host_matches, MID_ENTROPY_VALUE).is_none(),
        "the IDENTICAL value under a non-credential key must NOT surface, the bridge is credential-keyword-gated; matches: {host_matches:#?}"
    );
}

#[test]
fn ordinary_non_credential_assignment_keys_do_not_bridge() {
    let s = default_scanner();
    // None of these keys contains a credential-assignment prefilter stem, so the
    // bridge is never even offered the line.
    for key in ["name", "region", "version", "title", "label"] {
        let body = format!("{key}=gjbubxsu\n");
        let matches = scan(&s, &body);
        assert!(
            find(&matches, MID_ENTROPY_VALUE).is_none(),
            "`{key}=<value>` must not bridge; matches: {matches:#?}"
        );
    }
}

#[test]
fn bare_token_without_any_assignment_keyword_is_not_bridged() {
    // No `key=` at all: the assignment bridge has nothing to anchor on, and a
    // 2.5-entropy token is far too low for any isolated bare-entropy path, so
    // no generic detector identity appears.
    let s = default_scanner();
    let matches = scan(&s, "gjbubxsu\n");
    assert!(
        !bridged(&matches, MID_ENTROPY_VALUE),
        "a bare token with no credential keyword must not produce a generic finding; matches: {matches:#?}"
    );
}

// ---------------------------------------------------------------------------
// Host independence: the bridge is a scalar detector, produced on CpuFallback.
// ---------------------------------------------------------------------------

#[test]
fn bridge_is_produced_on_the_scalar_cpu_fallback_backend() {
    // Generic detector ownership must remain available on the pure-CPU
    // CpuFallback path with no Hyperscan/SIMD/GPU present. (All scans in this
    // file use CpuFallback; this test states that contract explicitly.)
    let s = default_scanner();
    let matches = scan(&s, "client_password=ufnlbbavawsdeecn\n");
    let m = find(&matches, HIGH_ENTROPY_VALUE).unwrap_or_else(|| {
        panic!("the generic bridge must fire on the host-independent CpuFallback path; matches: {matches:#?}")
    });
    assert!(GENERIC_DETECTOR_IDS.contains(&m.detector_id.as_ref()));
    assert_eq!(m.service.as_ref(), "generic");
}
