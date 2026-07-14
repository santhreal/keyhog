//! Regression: the `alphabet_targets` build doesn't allocate a throwaway
//! `Vec<String>` per phase-2 pattern.
//!
//! `alphabet_targets` (the literal/keyword set fed to `AlphabetScreen` and
//! `BigramBloom` at scanner-compile time) is `ac_literals` plus every phase-2
//! pattern's keywords. It used to extend with `keywords.clone()`: materializing
//! one throwaway `Vec<String>` per pattern (there are hundreds) and growing the
//! target by repeated reallocation. It now reserves the exact keyword total once
//! and clones each keyword straight in via `keywords.iter().cloned()` (Law 7).
//!
//! Byte-identical: the same keyword strings land in the same order, which the
//! full scan suite exercises (every scanner build feeds this set into the
//! alphabet screen + bigram bloom). This source-shape gate pins that the
//! per-pattern clone can't return.

fn read_src(rel: &str) -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(root.join(rel)).expect("source file readable")
}

#[test]
fn alphabet_targets_build_avoids_per_pattern_vec_clone() {
    let src = read_src("src/compiled_scanner/compile.rs");

    assert!(
        src.contains("alphabet_targets.extend(keywords.iter().cloned())"),
        "alphabet_targets must extend via keywords.iter().cloned() (no intermediate Vec)"
    );
    assert!(
        !src.contains("alphabet_targets.extend(keywords.clone())"),
        "alphabet_targets must NOT extend via keywords.clone() (allocates a throwaway Vec per pattern)"
    );
    assert!(
        src.contains("alphabet_targets.reserve(extra_keyword_count)"),
        "alphabet_targets must reserve the exact keyword total up front (no growth reallocation)"
    );
}
