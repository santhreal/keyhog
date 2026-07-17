//! Identifier / import-prefix contract for `entropy/keywords.rs`, reached via
//! the `keyhog_scanner::testing` facade. Migrated out of an inline
//! `#[cfg(test)]` block in `src/entropy/keywords.rs` to satisfy the scanner
//! folder contract (KH-GAP-013 `entropy_keywords_inline_tests_in_src`).

use keyhog_scanner::testing::{
    is_import_like_prefix_for_test as is_import_like_prefix,
    is_keyword_assignment_line_for_test as is_keyword_assignment_line,
    is_likely_innocuous_line_for_test as is_likely_innocuous_line,
    key_material_compact_keywords_for_test,
    normalized_assignment_keyword_is_credential_for_test as normalized_assignment_keyword_is_credential,
};

/// The import-prefix owner is space/paren-terminated: a real credential line
/// whose key merely BEGINS with `import`/`package` must still seed a keyword
/// context (regression for the `important_key`/`package_secret` false
/// negative), while genuine import/use/include declarations stay rejected.
#[test]
fn credential_line_beginning_with_import_word_still_seeds_context() {
    assert!(is_keyword_assignment_line(
        "important_key = \"wODc1jT8sK9pL2mN4qR7vX0zA3bE6h\"",
        &[]
    ));
    assert!(is_keyword_assignment_line(
        "package_secret = \"wODc1jT8sK9pL2mN4qR7vX0zA3bE6h\"",
        &[]
    ));
    assert!(!is_keyword_assignment_line("import foo.bar.Baz", &[]));
    assert!(!is_keyword_assignment_line("package com.example.app", &[]));
}

/// The single import-prefix owner drives BOTH the keyword-assignment reject
/// and the innocuous-line drop; the two used to carry divergent inline prefix
/// lists. If a second list reappears with different members this test breaks.
#[test]
fn import_prefix_owner_drives_both_checks() {
    for line in [
        "import x",
        "package y",
        "use z ",
        "from a import b",
        "require('m')",
        "include <h>",
        "#include <h>",
    ] {
        assert!(is_import_like_prefix(line.trim()), "{line:?}");
        assert!(is_likely_innocuous_line(line), "{line:?}");
    }
    for line in ["important = 1", "packageName = 2", "user token = 3"] {
        assert!(!is_import_like_prefix(line.trim()), "{line:?}");
    }
}

/// Every key-material anchor in the canonical vocabulary is recognized as a
/// credential keyword by the compact membership path, proving the split of
/// `KEY_MATERIAL_COMPACT_KEYWORDS` out of `CREDENTIAL_COMPACT_KEYWORDS`
/// preserved membership. A new anchor that fails this reaches neither gate.
#[test]
fn every_key_material_anchor_is_a_credential_keyword() {
    for w in key_material_compact_keywords_for_test() {
        assert!(
            normalized_assignment_keyword_is_credential(w),
            "key-material anchor {w:?} must be a credential keyword",
        );
    }
    // The two broad key-material words split out still resolve.
    assert!(normalized_assignment_keyword_is_credential("private_key"));
    assert!(normalized_assignment_keyword_is_credential("session_key"));
}

#[test]
fn credential_assignment_surface_preserves_boundaries_across_short_and_long_keys() {
    for line in [
        "DB_PASS=hunter2",
        "client.secret: opaque",
        "<private-key>opaque</private-key>",
        "Authorization: Bearer opaque",
        &format!("{}_TOKEN=opaque", "vendor".repeat(30)),
    ] {
        assert!(is_keyword_assignment_line(line, &[]), "{line:?}");
    }
    for line in [
        "let x = compute_value(42);",
        "CI_BYPASS=true",
        "compass = north",
        "passing_value: true",
        "package com.example.app",
    ] {
        assert!(!is_keyword_assignment_line(line, &[]), "{line:?}");
    }
}
