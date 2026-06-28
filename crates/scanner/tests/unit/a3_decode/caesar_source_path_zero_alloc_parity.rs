//! Zero-alloc Caesar source-path classification keeps case-insensitive +
//! both-separator + program-vs-text semantics after dropping the per-call
//! `replace('\\',"/").to_ascii_lowercase()` allocations.

use keyhog_scanner::testing::decode_caesar::{is_program_source_code_path, is_source_code_path};

#[test]
fn source_path_classification_is_case_insensitive_and_separator_agnostic() {
    // Case-insensitive extension match (the zero-alloc path relies on
    // ends_with_ignore_ascii_case, so UPPERCASE extensions must still match).
    assert!(is_program_source_code_path(Some("SRC/MAIN.RS")));
    assert!(is_program_source_code_path(Some("App/Service.Py")));
    assert!(is_program_source_code_path(Some("lib/Widget.TSX")));

    // Filename match over BOTH separators, case-insensitive (path_basename_bytes
    // splits on `/` and `\`; constants are lowercase).
    assert!(is_program_source_code_path(Some(r"DRIVERS\FOO\MAKEFILE")));
    assert!(is_program_source_code_path(Some("build/CMakeLists.txt")));
    assert!(is_program_source_code_path(Some(r"linux\net\Kconfig")));

    // Program-vs-text distinction: doc/text extensions are decode-noise for
    // Caesar (is_source_code_path TRUE) but are NOT program source for entropy
    // (is_program_source_code_path FALSE) — the two lists must stay separate.
    for doc in ["README.md", "notes/CHANGES.rst", "a/b/manual.TXT", "x.adoc"] {
        assert!(
            is_source_code_path(Some(doc)),
            "{doc} should be Caesar decode-noise (is_source_code_path)"
        );
        assert!(
            !is_program_source_code_path(Some(doc)),
            "{doc} must NOT be program source (entropy must not inherit text noise)"
        );
    }

    // Negatives: real config/secret carriers are neither.
    for carrier in ["config/secrets.env", "deploy/values.yaml", "data/dump.json"] {
        assert!(
            !is_program_source_code_path(Some(carrier)),
            "{carrier} must not be program source"
        );
        assert!(
            !is_source_code_path(Some(carrier)),
            "{carrier} must not be Caesar decode-noise"
        );
    }

    // None path is never source.
    assert!(!is_program_source_code_path(None));
    assert!(!is_source_code_path(None));
}
