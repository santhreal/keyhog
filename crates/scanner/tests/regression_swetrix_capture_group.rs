//! Regression: `swetrix-api-key` must capture the ISOLATED 32-hex key, not the
//! whole match (in BOTH keyword orders).
//!
//! The detector's second pattern was a single alternation
//! `X-Api-Key(cap1).*swetrix | swetrix.*X-Api-Key(cap2)`. The 32-hex value was
//! capture group 1 in the first branch but group 2 in the second, and the
//! detector declared `group = 1`. So when the SECOND branch matched (the
//! `swetrix` keyword appearing before the `X-Api-Key` header) group 1 never
//! participated: `engine/extract.rs`'s `locs.get(1).unwrap_or((full_start,
//! full_end))` silently fell back to the WHOLE match, reporting a garbage
//! credential (`swetrix…X-Api-Key…<key>`) that then failed the checksum/entropy
//! screens and silently dropped what was a real key. The fix splits the
//! alternation into two single-group patterns so group 1 always participates.
//!
//! The contract runner's `any_credential_contains` cannot catch this: the
//! garbage full-match CONTAINS the key, so the containment check passed both
//! before and after the fix. This test asserts the EXACT captured value.

use std::path::PathBuf;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;

const KEY: &str = "b539e4ae802deaca3a83216dd1580f3e";

/// Absolute path to `crates/scanner/../../detectors` from `CARGO_MANIFEST_DIR`,
/// so the test is cwd-independent. Replicated inline rather than pulled from
/// `tests/support` because aggregated `regression_*.rs` files are also compiled
/// as standalone test binaries, where the `support` module is not in scope.
fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

/// Scan `text` and return the credential captured by `swetrix-api-key`
/// specifically (the raw `scan` returns pre-dedup matches, so the vendor match
/// is present even if a generic detector also fires on the same value).
fn swetrix_credential(text: &str) -> String {
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("detectors directory loadable");
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "regression".into(),
            path: Some("swetrix.txt".into()),
            ..Default::default()
        },
    };
    let matches = scanner.scan(&chunk);
    let m = matches
        .iter()
        .find(|m| m.detector_id.as_ref() == "swetrix-api-key")
        .unwrap_or_else(|| {
            panic!(
                "swetrix-api-key did not fire on {text:?}; detectors that did fire: {:?}",
                matches
                    .iter()
                    .map(|m| m.detector_id.as_ref())
                    .collect::<Vec<_>>()
            )
        });
    m.credential.as_ref().to_string()
}

#[test]
fn swetrix_header_before_context_captures_only_the_key() {
    // Branch 1 (X-Api-Key … swetrix) (was already correct; guard it stays so).
    let cred = swetrix_credential(
        "X-Api-Key: b539e4ae802deaca3a83216dd1580f3e used by the swetrix client",
    );
    assert_eq!(
        cred, KEY,
        "header-before-swetrix must capture ONLY the 32-hex key, got {cred:?}"
    );
}

#[test]
fn swetrix_context_before_header_captures_only_the_key() {
    // Branch 2 (swetrix … X-Api-Key), the BUG order. Before the alternation was
    // split, this captured the whole `swetrix…X-Api-Key…<key>` match.
    let cred = swetrix_credential(
        "swetrix analytics client init; X-Api-Key: b539e4ae802deaca3a83216dd1580f3e",
    );
    assert_eq!(
        cred, KEY,
        "swetrix-before-header must capture ONLY the 32-hex key (not the whole \
         `swetrix…X-Api-Key…<key>` match); got {cred:?}"
    );
    // Pin the specific garbage-capture regression: the credential must not carry
    // the `swetrix` keyword or the `X-Api-Key` header the old full-match fallback
    // erroneously swept in.
    let lower = cred.to_ascii_lowercase();
    assert!(
        !lower.contains("swetrix") && !lower.contains("x-api-key"),
        "captured credential must be the isolated key, free of keyword/header context; got {cred:?}"
    );
}
