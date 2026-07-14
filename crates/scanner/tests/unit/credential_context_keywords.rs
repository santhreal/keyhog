use super::*;

/// The exact list that lived as the `CREDENTIAL_KEYWORDS` array inside
/// `entropy::scanner::keyword_context` before this migration. The Tier-B file
/// MUST parse to precisely this, in this order, the migration is a pure
/// relocation with zero behavioural change.
const LEGACY: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "db_pass",
    "db_password",
    "api_key",
    "apikey",
    "api-key",
    "auth",
    "authorization",
    "bearer",
    "_key",
    "-key",
    "token",
    "_token",
    "-token",
    "secret",
    "_secret",
    "-secret",
];

// ── the shipped file parses and matches the legacy array byte-for-byte ──
#[test]
fn bundled_file_parses() {
    parse_credential_context_keywords(CREDENTIAL_CONTEXT_KEYWORDS_TOML).unwrap();
}

#[test]
fn loaded_list_equals_legacy_in_order() {
    assert_eq!(credential_context_keywords(), LEGACY);
}

#[test]
fn count_is_exactly_nineteen() {
    assert_eq!(credential_context_keywords().len(), 19);
}

#[test]
fn accessor_is_memoized_to_the_same_instance() {
    assert!(std::ptr::eq(
        credential_context_keywords(),
        credential_context_keywords()
    ));
}

// ── invariants of the loaded vocabulary ──
#[test]
fn every_keyword_is_lowercase() {
    for keyword in credential_context_keywords() {
        assert_eq!(
            keyword,
            &keyword.to_ascii_lowercase(),
            "not lowercase: {keyword}"
        );
    }
}

#[test]
fn there_are_no_duplicates() {
    let mut seen = std::collections::BTreeSet::new();
    for keyword in credential_context_keywords() {
        assert!(seen.insert(keyword.as_str()), "duplicate: {keyword}");
    }
}

#[test]
fn no_keyword_is_empty() {
    for keyword in credential_context_keywords() {
        assert!(!keyword.is_empty());
    }
}

#[test]
fn every_byte_is_alnum_or_underscore_or_hyphen() {
    for keyword in credential_context_keywords() {
        assert!(
            keyword
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
            "unexpected char in {keyword}"
        );
    }
}

// ── specific membership (recall-load-bearing anchors) ──
#[test]
fn contains_the_core_password_words() {
    for expected in ["password", "passwd", "pwd", "db_pass", "db_password"] {
        assert!(credential_context_keywords().iter().any(|k| k == expected));
    }
}

#[test]
fn contains_the_api_key_spellings() {
    for expected in ["api_key", "apikey", "api-key"] {
        assert!(credential_context_keywords().iter().any(|k| k == expected));
    }
}

#[test]
fn contains_the_auth_words() {
    for expected in ["auth", "authorization", "bearer"] {
        assert!(credential_context_keywords().iter().any(|k| k == expected));
    }
}

#[test]
fn contains_the_separator_led_key_token_secret_suffixes() {
    for expected in ["_key", "-key", "_token", "-token", "_secret", "-secret"] {
        assert!(
            credential_context_keywords().iter().any(|k| k == expected),
            "missing suffix keyword {expected}"
        );
    }
}

#[test]
fn contains_the_bare_token_and_secret() {
    assert!(credential_context_keywords().iter().any(|k| k == "token"));
    assert!(credential_context_keywords().iter().any(|k| k == "secret"));
}

// ── negative membership: no speculative additions crept in ──
#[test]
fn does_not_contain_words_outside_the_migrated_set() {
    // Pin the exact set: `credential` and `passphrase` were NOT in the legacy
    // list (they are substring-covered elsewhere or handled by the exact
    // assignment table). A future recall change to add them must be a
    // deliberate, separately-reviewed edit (not an accident this test misses).
    for absent in ["credential", "credentials", "passphrase", "key", "pass"] {
        assert!(
            !credential_context_keywords().iter().any(|k| k == absent),
            "unexpected keyword {absent} present"
        );
    }
}

// ── the leading-separator entries survive the shared validator ──
#[test]
fn leading_separator_entries_are_preserved_verbatim() {
    let out = parse_credential_context_keywords(
        "[credential_context_keywords]\nkeywords = [\"_key\", \"-token\"]\n",
    )
    .unwrap();
    assert_eq!(out, vec!["_key", "-token"]);
}

// ── the loader inherits the shared validator's fail-closed rules ──
#[test]
fn rejects_uppercase_keyword() {
    let err = parse_credential_context_keywords(
        "[credential_context_keywords]\nkeywords = [\"Secret\"]\n",
    )
    .unwrap_err();
    assert!(err.contains("lowercase"), "got: {err}");
}

#[test]
fn rejects_duplicate_keyword() {
    let err = parse_credential_context_keywords(
        "[credential_context_keywords]\nkeywords = [\"token\", \"token\"]\n",
    )
    .unwrap_err();
    assert!(err.contains("duplicate"), "got: {err}");
}

#[test]
fn rejects_empty_keyword() {
    let err =
        parse_credential_context_keywords("[credential_context_keywords]\nkeywords = [\"\"]\n")
            .unwrap_err();
    assert!(err.contains("must not be empty"), "got: {err}");
}

#[test]
fn rejects_dot_separator_not_in_policy() {
    // `.` is intentionally excluded from this list's separators.
    let err = parse_credential_context_keywords(
        "[credential_context_keywords]\nkeywords = [\"api.key\"]\n",
    )
    .unwrap_err();
    assert!(err.contains("alphanumeric"), "got: {err}");
}

#[test]
fn rejects_unknown_toml_field() {
    let err = parse_credential_context_keywords(
        "[credential_context_keywords]\nkeywords = [\"token\"]\nextra = 1\n",
    )
    .unwrap_err();
    assert!(
        err.contains("invalid credential-context keywords"),
        "got: {err}"
    );
}

// ── the vocabulary drives credential-context recognition as a substring ──
#[test]
fn keywords_match_case_insensitively_as_substrings() {
    // Mirrors the exact call in keyword_context: ci_find_nonempty(line, keyword).
    let line = b"myApiKeyValue = aGVsbG8gd29ybGQ";
    assert!(credential_context_keywords()
        .iter()
        .any(|k| crate::ascii_ci::ci_find_nonempty(line, k.as_bytes())));
}

#[test]
fn a_line_with_no_credential_word_matches_nothing() {
    let line = b"const width = 1920; height = 1080";
    assert!(!credential_context_keywords()
        .iter()
        .any(|k| crate::ascii_ci::ci_find_nonempty(line, k.as_bytes())));
}
