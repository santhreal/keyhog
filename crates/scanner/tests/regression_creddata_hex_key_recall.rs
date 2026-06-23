//! Regression (KH-L-0110): the keyword bridge must SURFACE a complete pure-hex
//! value of canonical key length (32/48) under a STRONG credential keyword, and
//! must keep SUPPRESSING the look-alikes the lift deliberately excludes.
//!
//! Root cause this locks against: `suppression::shape::looks_like_bare_hex_digest`
//! (lengths 32|40|48|56|64|72|128) plus the random-byte/encoded-binary
//! shape arms suppressed EVERY keyword-bridged pure-hex value, dropping real
//! hex keys (`encryption_key = <hex48>`). On the real CredData corpus those are
//! genuine 96-100% of the time (hex48+kw 1033 POS / 0 NEG, hex32+kw 0.976);
//! lifting them recovered recall (CredData precision held/up, mirror precision
//! 0.9954 ≥ the 0.9945 floor — neither corpus plants hex32/hex48 hash-negatives,
//! only hex40/hex64, so the lift cannot reproduce the v31 `TOKEN=<hex>`
//! catastrophe). The exemption is bridge-path + strong-keyword + length-32/48
//! ONLY; the guards below pin every boundary.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

/// Build the shipped detector set + compiled scanner once.
fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    CompiledScanner::compile(detectors).expect("compile scanner")
}

/// Scan one line via the CPU fallback path (where the keyword bridge runs) and
/// return the set of captured credential strings.
fn credentials_for(scanner: &CompiledScanner, line: &str) -> Vec<String> {
    let chunk = Chunk {
        data: line.into(),
        metadata: ChunkMetadata::default(),
    };
    scanner.clear_fragment_cache();
    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .into_iter()
        .flatten()
        .map(|m| m.credential.to_string())
        .collect()
}

fn caught(scanner: &CompiledScanner, line: &str, value: &str) -> bool {
    credentials_for(scanner, line).iter().any(|c| c == value)
}

#[test]
fn strong_keyword_complete_hex32_and_hex48_are_surfaced() {
    let s = scanner();
    // Random (non-sequential, non-repetitive) hex of canonical key lengths under
    // strong cryptographic-key keywords — real keys on CredData, formerly dropped
    // by the bare-hex-digest gate. These literals match no named service detector
    // (no vendor prefix), so a hit proves the generic keyword-bridge lift fired.
    let hex32 = "3f8a9c2e1b7d4f6a8c0e2d4f6a8b0c1e";
    let hex48 = "a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f7081";
    assert!(
        caught(&s, &format!("api_key = \"{hex32}\""), hex32),
        "api_key = <random hex32> must surface (KH-L-0110 lift)"
    );
    assert!(
        caught(&s, &format!("encryption_key = \"{hex48}\""), hex48),
        "encryption_key = <random hex48> must surface (KH-L-0110 lift)"
    );
    assert!(
        caught(&s, &format!("secret = \"{hex48}\""), hex48),
        "secret = <random hex48> must surface (KH-L-0110 lift)"
    );
}

#[test]
fn lift_is_bounded_excluded_lengths_keywords_and_decoys_stay_suppressed() {
    let s = scanner();
    // hex64 (sha256 length) — a mirror hash-negative; NOT exempted. Exactly 64.
    let hex64 = "a3f5c8e1b9d27406f8a1c3e5b7d9f0214680ace2bdf135790246813579ace2bd";
    assert_eq!(hex64.len(), 64, "fixture must be exactly 64 hex chars");
    assert!(
        !caught(&s, &format!("secret = \"{hex64}\""), hex64),
        "hex64 (sha256 length) must stay suppressed — it is a mirror hash-negative"
    );
    // hex40 (sha1 / git-commit-sha length) — a mirror hash-negative; NOT exempted.
    let hex40 = "3f8a9c2e1b7d4f6a8c0e2d4f6a8b0c1e2d4f6a8b";
    assert_eq!(hex40.len(), 40, "fixture must be exactly 40 hex chars");
    assert!(
        !caught(&s, &format!("secret = \"{hex40}\""), hex40),
        "hex40 (sha1/git-sha length) must stay suppressed — it is a mirror hash-negative"
    );
    // Weak keyword `token` — deliberately excluded from the strong set.
    let hex32 = "5a6b7c8d9e0f1a2b3c4d5e6f70819203";
    assert_eq!(hex32.len(), 32);
    assert!(
        !caught(&s, &format!("token = \"{hex32}\""), hex32),
        "weak keyword `token` + hex32 must stay suppressed (not in the strong set)"
    );
    // Repetitive-run decoy under a strong keyword — the repetitive arm still runs.
    let repetitive32 = "deadc0dedeadc0dedeadc0dedeadc0de";
    assert!(
        !caught(
            &s,
            &format!("access_key = \"{repetitive32}\""),
            repetitive32
        ),
        "repetitive hex32 must stay suppressed (repetitive-run arm is preserved)"
    );
    // Repetitive decoy at an EXEMPT length (48) under a strong keyword: proves
    // the canonical-hex-key exemption skips the bare-hex-digest and pairwise
    // sequential-placeholder arms only; the repetitive-run arm still fires, so a
    // decoy is not surfaced.
    let repetitive48 = "abababababababababababababababababababababababab";
    assert_eq!(
        repetitive48.len(),
        48,
        "fixture must be exactly 48 hex chars"
    );
    assert!(
        !caught(
            &s,
            &format!("master_key = \"{repetitive48}\""),
            repetitive48
        ),
        "repetitive hex48 must stay suppressed even at an exempt length \
         (exemption does not disable the repetitive-run arm)"
    );
}
