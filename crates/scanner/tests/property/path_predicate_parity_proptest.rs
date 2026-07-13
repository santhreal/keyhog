//! Parity + behavioral truth for the path-component predicates in
//! `platform_compat::path`: `path_basename`, `path_basename_bytes`, and
//! `path_has_any_component`.
//!
//! `path_basename` (string, `rsplit`) and `path_basename_bytes` (raw bytes,
//! `rposition`) are TWO implementations of the SAME operation. "the final
//! component after the last `/` or `\`". The string version drives
//! context/suppression file attribution; the byte version drives the raw-bytes
//! suppression hot path (`suppression::path_filter`). If they ever disagree, the
//! same file is attributed one way on the string path and another on the byte
//! path, a silent suppression/recall bug of exactly the "two impls that drift"
//! class. The proptest pins them byte-for-byte over generated paths; the byte
//! version is ALSO checked standalone against a hand-rolled oracle on arbitrary
//! (incl. non-UTF-8) bytes, which the string version cannot be handed.
//!
//! `path_has_any_component` gates example-path suppression (a finding under
//! `test/` `examples/` `fixtures/` … is downranked). Its contract is EXACT
//! component match (NOT substring: `secrets/` must not match component
//! `secret`), case-insensitive, across BOTH separators. A false widen suppresses
//! real secrets in innocently-named dirs; a false narrow floods FPs. These pin
//! the contract directly rather than only through a full scan.

use keyhog_scanner::testing::{
    path_basename_bytes_for_test as basename_bytes, path_basename_for_test as basename,
    path_has_any_component_for_test as has_component,
};
use proptest::prelude::*;

/// Hand-rolled oracle for the byte basename, independent of the impl under test:
/// everything after the last `/` or `\`, or the whole slice when neither occurs.
fn oracle_basename_bytes(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|&b| b == b'/' || b == b'\\') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

// ── fixed vectors: byte basename ─────────────────────────────────────────────

#[test]
fn byte_basename_posix_windows_mixed_and_none() {
    assert_eq!(basename_bytes(b"/usr/local/bin/tool"), b"tool");
    assert_eq!(basename_bytes(br"C:\Users\admin\id_rsa"), b"id_rsa");
    assert_eq!(
        basename_bytes(br"repo/src\config\secret.env"),
        b"secret.env"
    );
    assert_eq!(basename_bytes(b"bare_name"), b"bare_name");
    assert_eq!(basename_bytes(b""), b"" as &[u8]);
    // A trailing separator yields an empty final component (matches rsplit/rposition).
    assert_eq!(basename_bytes(b"dir/"), b"" as &[u8]);
    assert_eq!(basename_bytes(br"dir\"), b"" as &[u8]);
}

#[test]
fn byte_basename_agrees_with_string_on_multibyte_components() {
    // `/` and `\` are ASCII (0x2F / 0x5C) and can never be a UTF-8 continuation
    // byte, so byte-search and char-search find the SAME cut points even amid
    // multibyte content (the two impls stay in lock-step).
    let p = "café/naïve/mañana.clé";
    assert_eq!(basename(p).as_bytes(), basename_bytes(p.as_bytes()));
    assert_eq!(basename(p), "mañana.clé");
}

// ── parity: string basename == byte basename (byte-for-byte) ─────────────────

proptest! {
    // Testing Contract: 8k cases. Per case = two O(n) scans over a <=~60-byte
    // path, no allocation beyond the built path string (cheap at 8k).
    #![proptest_config(ProptestConfig::with_cases(8_000))]

    /// The two implementations must agree byte-for-byte on every valid-UTF-8
    /// path. Paths are BUILT from components joined by random `/` or `\` (a pure
    /// random string almost never contains a separator, so this actually
    /// exercises the cut logic rather than the no-separator fast path).
    #[test]
    fn string_and_byte_basename_agree(
        components in prop::collection::vec("[A-Za-z0-9._-]{0,8}", 1..6),
        seps in prop::collection::vec(prop::bool::ANY, 6),
        lead in prop::bool::ANY,
    ) {
        let mut path = String::new();
        if lead {
            path.push(if seps[0] { '/' } else { '\\' });
        }
        for (i, c) in components.iter().enumerate() {
            if i > 0 {
                path.push(if seps[i % seps.len()] { '/' } else { '\\' });
            }
            path.push_str(c);
        }
        let via_str = basename(&path).as_bytes();
        let via_bytes = basename_bytes(path.as_bytes());
        prop_assert_eq!(
            via_str, via_bytes,
            "path_basename vs path_basename_bytes diverged on {:?}", path
        );
    }

    /// The byte version must equal the independent oracle on ARBITRARY bytes,
    /// including non-UTF-8, separators are over-represented so the cut path is
    /// hit frequently.
    #[test]
    fn byte_basename_matches_oracle_on_arbitrary_bytes(
        bytes in prop::collection::vec(
            prop_oneof![Just(b'/'), Just(b'\\'), any::<u8>()],
            0..96,
        )
    ) {
        prop_assert_eq!(basename_bytes(&bytes), oracle_basename_bytes(&bytes));
    }
}

// ── path_has_any_component: exact + case-insensitive + both separators ───────

#[test]
fn has_component_matches_exact_component_case_insensitively() {
    assert!(has_component("src/test/App.java", &["test"]));
    assert!(has_component(r"src\TEST\App.java", &["test"]));
    assert!(has_component("a/Examples/b", &["examples"]));
    // First-or-last component is included in the scan.
    assert!(has_component("fixtures/x", &["fixtures"]));
    assert!(has_component("x/fixtures", &["fixtures"]));
    // Any-of semantics: matches if ANY listed component is present.
    assert!(has_component(
        "src/examples/x",
        &["test", "examples", "fixtures"]
    ));
}

#[test]
fn has_component_requires_a_whole_component_not_a_substring() {
    // Exact component, NOT substring, a widen here would suppress real secrets
    // under an innocently-named dir.
    assert!(!has_component("secrets/prod.key", &["secret"]));
    assert!(!has_component("mytest/x", &["test"]));
    assert!(!has_component("test_helpers/x", &["test"]));
}

#[test]
fn has_component_no_match_and_empty_cases() {
    assert!(!has_component("src/main/app.rs", &["test", "examples"]));
    assert!(!has_component("", &["test"]));
    assert!(!has_component("anything", &[]));
}
