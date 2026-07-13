//! Regression: the generic keyword-bridge low-entropy floor.
//!
//! The generic-assignment bridge (`engine/phase2_generic.rs` →
//! `generic_value_shape_rejected` → `adjudicate::generic_bridge_entropy_below_floor`)
//! applies the active detector's per-family Shannon-entropy floor as its
//! very first suppression gate. When `generic_keyword_low_entropy` is ON (the
//! shipped default) a keyword-anchored value is judged against the
//! `generic-keyword-secret` family floor of **1.5** bits/byte; when it is OFF the
//! stricter `generic-secret` family floor applies (**2.8** for values of length
//! <= 24). The band `[1.5, 2.8)` is therefore surfaced ONLY because of the
//! keyword low-entropy floor, a genuine weak/random password like
//! `GRAPHITE_PASS=gjbubxsu` (Shannon entropy exactly 2.5) lives in that band.
//!
//! Every entropy value asserted here is the SAME number the engine feeds the
//! floor gate: `engine::pipeline::match_entropy` (feature `entropy`) resolves to
//! `entropy::fast::shannon_entropy_simd`, which the crate re-exports for tests as
//! `keyhog_scanner::testing::entropy_fast::shannon_entropy_simd`. So the math
//! assertions and the end-to-end gate share one source of truth (no epsilon slop
//! between "what the test computes" and "what the gate sees").

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch, Severity};
use keyhog_scanner::testing::entropy_fast::shannon_entropy_simd;
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};

/// `generic-keyword-secret` detector-local floor (single
/// bucket). A keyword-anchored candidate at or below this bits/byte value is
/// dropped even with the low-entropy floor ON.
const KEYWORD_SECRET_FLOOR: f64 = 1.5;
/// `generic-secret` detector-local floor for length <= 24 (the first bucket).
/// This is the floor the bridge falls back to when
/// `generic_keyword_low_entropy` is OFF.
const GENERIC_SECRET_SHORT_FLOOR: f64 = 2.8;

/// The stable identity the generic bridge stamps on every emitted match
/// (`pipeline::build_synthetic_raw_match` in `engine/phase2_generic.rs`).
const BRIDGE_DETECTOR_ID: &str = "generic-secret";
const BRIDGE_DETECTOR_NAME: &str = "Generic Secret (Key=Value)";
const BRIDGE_SERVICE: &str = "generic";

/// Compile the full shipped detector set with an explicit
/// `generic_keyword_low_entropy` toggle. `min_confidence` is pinned to 0.0 so the
/// ONLY variable between the ON/OFF scanners is the entropy floor selection, the
/// confidence gate never confounds a floor assertion.
fn scanner_with_keyword_floor(enabled: bool) -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let mut cfg = ScannerConfig::default();
    cfg.min_confidence = 0.0;
    cfg.generic_keyword_low_entropy = enabled;
    CompiledScanner::compile(detectors)
        .expect("compile scanner")
        .with_config(cfg)
}

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

fn surfaced(scanner: &CompiledScanner, body: &str, credential: &str) -> bool {
    find(&scan(scanner, body), credential).is_some()
}

// ---------------------------------------------------------------------------
// Group A: entropy math (the exact bits/byte values the floor gate compares).
// These pin WHY each fixture lands where it does relative to the two floors.
// ---------------------------------------------------------------------------

#[test]
fn gjbubxsu_entropy_is_exactly_two_point_five_and_sits_in_the_bridge_band() {
    // b:2 u:2 g/j/x/s:1 over 8 bytes -> -(2*0.25*log2 0.25 + 4*0.125*log2 0.125)
    // = -(-0.5 - 1.5) = 2.5 exactly.
    let h = shannon_entropy_simd(b"gjbubxsu");
    assert!(
        (h - 2.5).abs() < 1e-12,
        "gjbubxsu Shannon entropy must be 2.5 bits/byte, got {h}"
    );
    // Strictly inside [keyword floor, generic floor): surfaced ONLY by the
    // keyword low-entropy floor.
    assert!(
        h > KEYWORD_SECRET_FLOOR,
        "2.5 must clear the 1.5 keyword floor"
    );
    assert!(
        h < GENERIC_SECRET_SHORT_FLOOR,
        "2.5 must be below the 2.8 generic-secret floor"
    );
}

#[test]
fn krbykalt_entropy_is_exactly_two_point_seven_five_just_below_generic_floor() {
    // k:2 over 8 bytes, six singles -> -(0.25*log2 0.25 + 6*0.125*log2 0.125)
    // = -(-0.5 - 2.25) = 2.75 exactly. 0.05 below the 2.8 generic floor.
    let h = shannon_entropy_simd(b"krbykalt");
    assert!(
        (h - 2.75).abs() < 1e-12,
        "krbykalt Shannon entropy must be 2.75 bits/byte, got {h}"
    );
    assert!(h < GENERIC_SECRET_SHORT_FLOOR && h > KEYWORD_SECRET_FLOOR);
}

#[test]
fn dzdvnffvqp_entropy_is_between_the_two_floors() {
    // three pairs (0.2) + four singles (0.1) over 10 bytes ~= 2.721928.
    let h = shannon_entropy_simd(b"dzdvnffvqp");
    assert!(
        (h - 2.721_928).abs() < 1e-5,
        "dzdvnffvqp Shannon entropy must be ~2.721928 bits/byte, got {h}"
    );
    assert!(h > KEYWORD_SECRET_FLOOR && h < GENERIC_SECRET_SHORT_FLOOR);
}

#[test]
fn ufnlbbavawsdeecn_entropy_is_exactly_three_point_five_above_generic_floor() {
    // 8 singles (1/16) + 4 pairs (1/8) over 16 bytes -> -(-2.0 - 1.5) = 3.5 exactly.
    let h = shannon_entropy_simd(b"ufnlbbavawsdeecn");
    assert!(
        (h - 3.5).abs() < 1e-12,
        "ufnlbbavawsdeecn Shannon entropy must be 3.5 bits/byte, got {h}"
    );
    // Above BOTH floors: the keyword toggle must not change its fate.
    assert!(
        h > GENERIC_SECRET_SHORT_FLOOR,
        "3.5 must clear the 2.8 generic floor"
    );
}

#[test]
fn repeated_pair_token_entropy_is_one_bit_below_the_keyword_floor() {
    // a:4 1:4 over 8 bytes -> two symbols at 0.5 -> 1.0 bit exactly. This is the
    // sub-1.5 regime the keyword floor itself rejects.
    let h = shannon_entropy_simd(b"a1a1a1a1");
    assert!(
        (h - 1.0).abs() < 1e-12,
        "a1a1a1a1 Shannon entropy must be 1.0 bit/byte, got {h}"
    );
    assert!(
        h < KEYWORD_SECRET_FLOOR,
        "1.0 must be below the 1.5 keyword floor"
    );
}

// ---------------------------------------------------------------------------
// Group B: the low-entropy floor SURFACES a real weak/random password.
// ---------------------------------------------------------------------------

#[test]
fn low_entropy_password_surfaces_under_password_keyword() {
    let s = scanner_with_keyword_floor(true);
    let matches = scan(&s, "password = \"gjbubxsu\"\n");
    let m = find(&matches, "gjbubxsu").unwrap_or_else(|| {
        panic!("gjbubxsu (entropy 2.5, above the 1.5 keyword floor) must surface under `password =`; matches: {matches:#?}")
    });
    assert_eq!(
        m.detector_id.as_ref(),
        BRIDGE_DETECTOR_ID,
        "surfaced via the generic keyword bridge"
    );
}

#[test]
fn surfaced_bridge_match_carries_the_generic_secret_identity_and_reported_entropy() {
    let s = scanner_with_keyword_floor(true);
    let matches = scan(&s, "GRAPHITE_PASS=gjbubxsu\n");
    let m = find(&matches, "gjbubxsu")
        .unwrap_or_else(|| panic!("GRAPHITE_PASS=gjbubxsu must surface; matches: {matches:#?}"));
    assert_eq!(m.detector_id.as_ref(), BRIDGE_DETECTOR_ID);
    assert_eq!(m.detector_name.as_ref(), BRIDGE_DETECTOR_NAME);
    assert_eq!(m.service.as_ref(), BRIDGE_SERVICE);
    assert_eq!(m.severity, Severity::Medium);
    // The reported entropy IS the value the floor gate compared: 2.5 exactly.
    let reported = m
        .entropy
        .expect("generic bridge stamps the Shannon entropy");
    assert!(
        (reported - 2.5).abs() < 1e-9,
        "reported entropy must equal the 2.5 the floor gate saw, got {reported}"
    );
}

#[test]
fn reported_entropy_equals_the_shared_simd_floor_input() {
    let s = scanner_with_keyword_floor(true);
    let matches = scan(&s, "SES_PASS=dzdvnffvqp\n");
    let m = find(&matches, "dzdvnffvqp")
        .unwrap_or_else(|| panic!("SES_PASS=dzdvnffvqp must surface; matches: {matches:#?}"));
    let reported = m.entropy.expect("entropy stamped");
    let recomputed = shannon_entropy_simd(b"dzdvnffvqp");
    assert!(
        (reported - recomputed).abs() < 1e-9,
        "the match entropy ({reported}) must equal the crate's shannon_entropy_simd ({recomputed}), one source of truth for the floor gate"
    );
}

// ---------------------------------------------------------------------------
// Group C: the floor is LOAD-BEARING (flip it and the same value's fate flips).
// Only `generic_keyword_low_entropy` differs between the two scanners.
// ---------------------------------------------------------------------------

#[test]
fn keyword_floor_toggle_is_load_bearing_for_gjbubxsu() {
    let body = "GRAPHITE_PASS=gjbubxsu\n";
    let on = scanner_with_keyword_floor(true);
    let off = scanner_with_keyword_floor(false);
    assert!(
        surfaced(&on, body, "gjbubxsu"),
        "floor ON (1.5): entropy 2.5 clears it, value surfaces"
    );
    assert!(
        !surfaced(&off, body, "gjbubxsu"),
        "floor OFF (2.8): entropy 2.5 is below it, value is suppressed, the low-entropy floor is the ONLY reason it surfaced"
    );
}

#[test]
fn password_keyword_value_dropped_when_floor_reverts_to_generic() {
    let body = "password = \"gjbubxsu\"\n";
    assert!(surfaced(
        &scanner_with_keyword_floor(true),
        body,
        "gjbubxsu"
    ));
    assert!(!surfaced(
        &scanner_with_keyword_floor(false),
        body,
        "gjbubxsu"
    ));
}

#[test]
fn krbykalt_just_below_generic_floor_flips_with_the_toggle() {
    // 2.75 < 2.8 by exactly 0.05: a boundary-adjacent value that the generic
    // floor rejects but the keyword floor keeps.
    let body = "JENKINS_PASS=krbykalt\n";
    assert!(
        surfaced(&scanner_with_keyword_floor(true), body, "krbykalt"),
        "2.75 clears the 1.5 keyword floor"
    );
    assert!(
        !surfaced(&scanner_with_keyword_floor(false), body, "krbykalt"),
        "2.75 is below the 2.8 generic-secret floor"
    );
}

#[test]
fn value_above_generic_floor_surfaces_regardless_of_toggle() {
    // Entropy 3.5 clears BOTH floors, so the keyword toggle must not change it
    // proves the toggle only governs the [1.5, 2.8) band, not all generic values.
    let body = "password = \"ufnlbbavawsdeecn\"\n";
    assert!(
        surfaced(&scanner_with_keyword_floor(true), body, "ufnlbbavawsdeecn"),
        "3.5 surfaces with the keyword floor ON"
    );
    assert!(
        surfaced(&scanner_with_keyword_floor(false), body, "ufnlbbavawsdeecn"),
        "3.5 also surfaces with the keyword floor OFF (above the 2.8 generic floor)"
    );
}

#[test]
fn high_precision_preset_disables_the_keyword_floor_and_drops_the_weak_password() {
    // The shipped `high_precision()` preset flips generic_keyword_low_entropy OFF
    // (restores the strict generic-secret floor). A 2.5-entropy keyword value
    // must NOT survive that preset.
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let s = CompiledScanner::compile(detectors)
        .expect("compile scanner")
        .with_config(ScannerConfig::high_precision());
    assert!(
        !surfaced(&s, "GRAPHITE_PASS=gjbubxsu\n", "gjbubxsu"),
        "high_precision restores the 2.8 floor; entropy 2.5 must be dropped"
    );
}

// ---------------------------------------------------------------------------
// Group D: negative twins (the low floor is NOT a blanket admit).
// ---------------------------------------------------------------------------

#[test]
fn unrelated_low_entropy_token_is_not_surfaced_without_a_credential_keyword() {
    // Same random low-entropy value, but under a NON-credential key (`region`
    // shares no substring with any generic credential keyword): no keyword bridge
    // fires, and 2.5 is far too low for any isolated-bare entropy path, so nothing
    // is emitted even with the keyword floor ON.
    let s = scanner_with_keyword_floor(true);
    let matches = scan(&s, "region = \"gjbubxsu\"\n");
    assert!(
        find(&matches, "gjbubxsu").is_none(),
        "an unrelated `region =` low-entropy token must not surface; matches: {matches:#?}"
    );
}

#[test]
fn dictionary_word_under_keyword_stays_suppressed_despite_the_low_floor() {
    // `defaultPassword` clears the 1.5 keyword floor on entropy alone, yet it is a
    // pronounceable dictionary identifier the shape gauntlet rejects, proving the
    // low floor does not by itself admit a value.
    let s = scanner_with_keyword_floor(true);
    let matches = scan(&s, "password = defaultPassword\n");
    assert!(
        find(&matches, "defaultPassword").is_none(),
        "a dictionary identifier must stay suppressed even under the low keyword floor; matches: {matches:#?}"
    );
}

#[test]
fn dictionary_word_entropy_clears_the_keyword_floor_so_suppression_is_shape_not_entropy() {
    // Documents WHY the previous test is a real shape-gate check and not an
    // accidental entropy drop: `defaultPassword`'s entropy is well above 1.5.
    let h = shannon_entropy_simd(b"defaultPassword");
    assert!(
        h > KEYWORD_SECRET_FLOOR,
        "defaultPassword entropy {h} must clear the 1.5 keyword floor (so its suppression is the shape gauntlet, not the floor)"
    );
}
