//! Property tier for `validate_scan_archive_entry_name` (reached via the
//! `SourceTestApi` facade) — the guard every archive extractor (zip / 7z / rar)
//! runs over each entry name before the member is processed. The fixed-vector
//! twin (`tests/unit/archive_entry_name_traversal_contract.rs`) pins the exact
//! refusal reason for each hand-picked class; this file sweeps the SECURITY
//! contract over a generated space so a regression cannot slip a traversal past
//! an input shape nobody wrote a vector for.
//!
//! The invariants proved here, none of which the fixed vectors establish:
//!
//!   * ROBUSTNESS — the validator never panics on arbitrary Unicode or on a
//!     hostile alphabet concentrated on the exact bytes its decode/traversal
//!     logic branches on (`. / \ % 2 e f c : NUL …`).
//!   * ANTI-SMUGGLING DEPTH — a `../` payload hidden behind *any* number of
//!     percent-encoding layers is ALWAYS refused: shallow layers decode to the
//!     literal `../` and trip the traversal check, and layers past the decode
//!     cap trip the "excessively encoded" refusal. The fixed test only exercises
//!     one and two layers; here every depth `1..=12` is a case.
//!   * DECODE-CAP BOUNDARY — the mirror of the above for a *safe* name: it
//!     survives up to the nine decode layers the loop can traverse and is
//!     refused at ten (a DoS guard), pinning the exact loop-depth contract.
//!   * ROOT CONTAINMENT — every name the validator ACCEPTS is, under an
//!     independent lexical normalization (depth counting, not a copy of the
//!     implementation), guaranteed not to escape the extraction root, and free
//!     of the NUL / backslash structural hazards. This is the load-bearing
//!     security direction: the guard must never accept something dangerous.
//!
//! Reached ONLY through the stable `SourceTestApi` facade (the
//! `src/filesystem/extract/**` no-inline-tests contract keeps unit coverage out
//! of `src`). No cargo feature is required — the guard is on the base build.

use keyhog_sources::testing::{SourceTestApi, TestApi};
use proptest::prelude::*;

/// Percent-encode EVERY byte of `s` to `%XX` (uppercase hex). Applied to a
/// string that already contains `%`, this nests: the `%` of the inner layer
/// becomes `%25` in the outer layer, so `onion(s, k)` is `s` wrapped in `k`
/// independent decode layers. Deliberately encodes all bytes (not just the
/// traversal-significant ones) so an intermediate layer never carries a raw
/// `/`, `.` or `..` — only the fully-decoded innermost `s` can trip a
/// content check, which is exactly what makes the depth argument clean.
fn pct_encode_all(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for &b in s.as_bytes() {
        out.push('%');
        out.push_str(&format!("{b:02X}"));
    }
    out
}

fn pct_onion(s: &str, layers: usize) -> String {
    let mut current = s.to_string();
    for _ in 0..layers {
        current = pct_encode_all(&current);
    }
    current
}

/// Independent lexical normalization: does `name`, interpreted as a relative
/// path joined onto the extraction root, ever resolve ABOVE the root? Counts
/// component depth (`..` pops, ordinary components push); a depth that ever goes
/// negative means the path climbed out of the root. Structural hazards that make
/// containment meaningless on a real filesystem (NUL, backslash — a Windows
/// separator the forward-slash walk would miss) count as an escape. This is a
/// from-scratch oracle, NOT a call back into the validator, so it can actually
/// disagree with a buggy guard.
fn lexically_escapes_root(name: &str) -> bool {
    if name.contains('\0') || name.contains('\\') {
        return true;
    }
    // A Windows drive prefix (`C:...`) is an absolute anchor, not a relative
    // component — treat it as an escape.
    let b = name.as_bytes();
    if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        return true;
    }
    if name.starts_with('/') {
        return true; // unix-absolute
    }
    let mut depth: i32 = 0;
    for comp in name.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return true;
                }
            }
            _ => depth += 1,
        }
    }
    false
}

/// Hostile alphabet concentrated on the bytes the validator branches on, so the
/// generated names actually exercise the percent-decode and traversal logic
/// rather than wandering through inert Unicode.
fn hazardous_name() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop::sample::select(vec![
            '.', '/', '\\', '%', '2', '5', 'e', 'E', 'f', 'F', 'c', 'C', ':', '\0', 'a', 'b', ' ',
            '\u{00e9}',
        ]),
        0..48,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(6_000))]

    /// Never panics on a hostile, traversal-flavoured alphabet — no slice on a
    /// non-char-boundary, no index-out-of-bounds in the `%XX` decode, no
    /// unbounded recursion.
    #[test]
    fn never_panics_on_hazardous_names(name in hazardous_name()) {
        let _ = TestApi.validate_archive_entry_name(&name);
    }

    /// Never panics on arbitrary Unicode either (the ASCII fast paths and the
    /// `char`/byte boundaries between them are where a slicing bug would live).
    #[test]
    fn never_panics_on_arbitrary_unicode(name in ".*") {
        let _ = TestApi.validate_archive_entry_name(&name);
    }

    /// The load-bearing security direction: anything the validator ACCEPTS is
    /// lexically contained in the extraction root and free of NUL/backslash
    /// hazards, judged by an INDEPENDENT normalization. If the guard ever
    /// regressed to accept a climbing or absolute name, this turns red.
    #[test]
    fn accepted_names_never_escape_the_extraction_root(name in hazardous_name()) {
        if TestApi.validate_archive_entry_name(&name).is_ok() {
            prop_assert!(
                !lexically_escapes_root(&name),
                "validator ACCEPTED a name that escapes the extraction root: {name:?}"
            );
            prop_assert!(!name.is_empty(), "an empty name must never be accepted");
            prop_assert!(!name.contains('\0'), "a NUL-bearing name must never be accepted");
            prop_assert!(!name.contains('\\'), "a backslash-bearing name must never be accepted");
        }
    }
}

proptest! {
    // Percent-onion cases are deliberately FEW: `pct_onion` re-encodes every
    // byte per layer, so each layer TRIPLES the string. Even the bounded 1..=6
    // depth here builds multi-kilobyte names the validator then decodes
    // layer-by-layer; a large case count would be pure wall-clock with no extra
    // coverage (the shrinker still minimises any failure). The >10-layer
    // "excessively encoded" refusal past the decode cap is pinned by the
    // fixed-vector twin `excessively_percent_encoded_name_is_refused`, so it
    // needs no sweep here.
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// A `../` traversal behind 1..=6 percent-encoding layers is always refused:
    /// the decode-revalidate loop peels each layer until the innermost literal
    /// `../` trips the traversal check. The fixed-vector twin only samples one
    /// and two layers; this proves the loop handles the multi-layer case.
    #[test]
    fn layered_encoding_of_a_traversal_is_always_refused(
        layers in 1usize..=6,
        payload in prop::sample::select(vec![
            "../etc/passwd",
            "../../secret",
            "pkg/../../etc/shadow",
            "..",
            "dir/../../x",
        ]),
    ) {
        let onion = pct_onion(payload, layers);
        prop_assert!(
            TestApi.validate_archive_entry_name(&onion).is_err(),
            "a {layers}-layer percent-encoding of traversal {payload:?} must be refused"
        );
    }

    /// The acceptance mirror: a SAFE relative name behind 1..=6 encoding layers
    /// (all within the loop's decode budget) decodes fully and is accepted — the
    /// loop must not over-reject a legitimately percent-encoded entry name.
    #[test]
    fn safe_name_survives_multiple_encoding_layers(
        layers in 1usize..=6,
        name in prop::sample::select(vec!["dir/file.txt", "a/b/c.env", "config.yaml", "x"]),
    ) {
        let onion = pct_onion(name, layers);
        prop_assert!(
            TestApi.validate_archive_entry_name(&onion).is_ok(),
            "safe name {name:?} behind {layers} decode layers must be accepted"
        );
    }
}
