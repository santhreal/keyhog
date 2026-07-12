//! Property tier for the allowlist PATH-GLOB matcher (`Allowlist::is_path_ignored`
//! → the hand-rolled segment-NFA in `allowlist/glob.rs`). This is a SECURITY
//! matcher: an over-match silently SUPPRESSES a real finding (the secret ships
//! unreported), an under-match fails to honor an operator's `.keyhogignore`. The
//! existing `regression_allowlist_*` files pin fixed decisions; this file locks
//! the matcher's INVARIANTS over arbitrary inputs (proptest, 10k) plus a set of
//! hand-verified semantics examples.
//!
//! Semantics (verified against `glob.rs`): a pattern's segments must match the
//! WHOLE path (the NFA accepts only when it consumes every path segment). `**`
//! matches any run of segments INCLUDING ZERO; a non-`**` segment matches
//! exactly one path segment; within a segment `*` is a run-of-chars wildcard
//! (no `?`). A trailing-slash pattern (`dir/`) auto-expands to `dir/**`.
//! Paths/patterns are normalized (`.`/`..` resolved, `\` → `/`) first.
//!
//! Everything drives the STABLE PUBLIC surface: `Allowlist::default()` +
//! the public `ignored_paths: Vec<String>` field + `is_path_ignored` (which
//! rebuilds its precompiled index when `ignored_paths` was mutated directly).

use keyhog_core::Allowlist;
use proptest::prelude::*;

/// Does `path` match ANY of `globs`? Fresh allowlist per call; setting
/// `ignored_paths` directly forces `is_path_ignored` to rebuild the glob index.
fn ignored(globs: &[&str], path: &str) -> bool {
    let mut al = Allowlist::default();
    al.ignored_paths = globs.iter().map(|s| (*s).to_string()).collect();
    al.is_path_ignored(path)
}

/// A safe path segment: lowercase letters only — no `*` (would become a
/// wildcard), no `/` (segment separator), no `.`/`..` (normalization would alter
/// it), never empty. So a joined path equals its own literal glob pattern.
fn seg() -> impl Strategy<Value = String> {
    "[a-z]{1,8}"
}

/// An arbitrary glob string over the matcher's real alphabet (literals, `*`,
/// `/`, hence `**`), bounded so it never trips the oversize fail-safe.
fn glob() -> impl Strategy<Value = String> {
    "[a-z*/]{0,24}"
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// Pure: the same (globs, path) always yields the same verdict.
    #[test]
    fn prop_deterministic(g in glob(), segs in prop::collection::vec(seg(), 1..6)) {
        let path = segs.join("/");
        prop_assert_eq!(ignored(&[&g], &path), ignored(&[&g], &path));
    }

    /// An empty allowlist ignores NOTHING — no path is ever suppressed.
    #[test]
    fn prop_empty_allowlist_ignores_nothing(segs in prop::collection::vec(seg(), 1..6)) {
        prop_assert!(!ignored(&[], &segs.join("/")));
    }

    /// Suppression is ANY-of the globs, so adding more globs is MONOTONIC: a path
    /// already ignored stays ignored, regardless of glob order.
    #[test]
    fn prop_union_is_monotonic(g1 in glob(), g2 in glob(), segs in prop::collection::vec(seg(), 1..6)) {
        let path = segs.join("/");
        if ignored(&[&g1], &path) {
            prop_assert!(ignored(&[&g1, &g2], &path));
            prop_assert!(ignored(&[&g2, &g1], &path));
        }
    }

    /// `**` alone matches EVERY path (any number of segments, including the empty
    /// path) — the "ignore everything" escape hatch.
    #[test]
    fn prop_double_star_matches_any_path(segs in prop::collection::vec(seg(), 0..6)) {
        prop_assert!(ignored(&["**"], &segs.join("/")));
    }

    /// A pure-literal pattern equal to the path matches it EXACTLY: it matches
    /// the path itself, but NOT a longer path that extends it, and NOT a proper
    /// prefix of it (the NFA must consume every path segment).
    #[test]
    fn prop_exact_literal_is_whole_path_anchored(segs in prop::collection::vec(seg(), 1..6)) {
        let path = segs.join("/");
        let longer = format!("{path}/zzz");
        prop_assert!(ignored(&[&path], &path));
        prop_assert!(!ignored(&[&path], &longer));
        if segs.len() > 1 {
            let shorter = segs[..segs.len() - 1].join("/");
            prop_assert!(!ignored(&[&path], &shorter));
        }
    }

    /// Normalization is applied to the path before matching: a leading `./` and
    /// `\`-separators are equivalent to the plain `/`-form.
    #[test]
    fn prop_path_normalization_equivalence(segs in prop::collection::vec(seg(), 1..6)) {
        let path = segs.join("/");
        let g = [path.as_str()];
        let dotted = format!("./{path}");
        let backslashed = path.replace('/', "\\");
        prop_assert_eq!(ignored(&g, &dotted), ignored(&g, &path));
        prop_assert_eq!(ignored(&g, &backslashed), ignored(&g, &path));
    }
}

/// Hand-verified semantics (each traced against `glob_match_segments` /
/// `segment_match`): the exact behavior a future refactor must preserve.
#[test]
fn allowlist_glob_semantics_examples() {
    // Literal pattern is whole-path anchored.
    assert!(ignored(&["a/b/c"], "a/b/c"));
    assert!(!ignored(&["a/b/c"], "a/b"));
    assert!(!ignored(&["a/b/c"], "a/b/c/d"));
    assert!(!ignored(&["a/b/c"], "a/b/x"));

    // Single-segment `*` does NOT cross a path separator.
    assert!(ignored(&["*.env"], "x.env"));
    assert!(ignored(&["*.env"], ".env"));
    assert!(!ignored(&["*.env"], "x.txt"));
    assert!(!ignored(&["*.env"], "dir/x.env"));

    // `**/` prefix floats the match to any depth.
    assert!(ignored(&["**/*.env"], "x.env"));
    assert!(ignored(&["**/*.env"], "dir/x.env"));
    assert!(ignored(&["**/*.env"], "a/b/c.env"));
    assert!(!ignored(&["**/*.env"], "a/b/c.txt"));

    // Trailing `/**` (and the `dir/` sugar for it) matches the subtree AND the
    // directory itself, because `**` matches zero segments.
    assert!(ignored(&["foo/**"], "foo"));
    assert!(ignored(&["foo/**"], "foo/a"));
    assert!(ignored(&["foo/**"], "foo/a/b"));
    assert!(!ignored(&["foo/**"], "bar/a"));
    assert!(ignored(&["build/"], "build"));
    assert!(ignored(&["build/"], "build/x"));
    assert!(!ignored(&["build/"], "builds"));

    // Mid-path single `*` spans EXACTLY one segment.
    assert!(ignored(&["src/*/mod.rs"], "src/a/mod.rs"));
    assert!(!ignored(&["src/*/mod.rs"], "src/mod.rs"));
    assert!(!ignored(&["src/*/mod.rs"], "src/a/b/mod.rs"));

    // `**` alone is total.
    assert!(ignored(&["**"], "anything/at/all"));
    assert!(ignored(&["**"], "x"));
}
