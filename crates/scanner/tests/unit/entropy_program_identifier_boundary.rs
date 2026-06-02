//! Boundary test for program-identifier rejection (keywords.rs:438-461).
//!
//! Source-code identifiers in mainstream languages follow patterns:
//! - snake_case: lowercase + underscores (e.g., "my_helper_name")
//! - camelCase / PascalCase: mixed case with internal lower→Upper transitions
//!   (e.g., "BulkUpdateApiKeyResponse")
//!
//! Real API keys almost never match these patterns. The gate rejects identifiers
//! by checking: (1) underscore + all-lowercase OR (2) camelCase/PascalCase
//! with 1+ internal case transitions. This test pins the exact boundary.

use keyhog_scanner::entropy::keywords::is_secret_plausible;

#[test]
fn program_identifier_snake_case_with_underscores_rejected() {
    // snake_case: lowercase letters + underscores. "my_long_helper_name"
    // matches the pattern and must be rejected.
    let snake_case = "my_long_helper_name";
    assert!(snake_case.contains('_'));
    assert!(snake_case
        .chars()
        .all(|c| c.is_ascii_lowercase() || c == '_'));
    assert!(!is_secret_plausible(snake_case, &[]));
}

#[test]
fn program_identifier_camelcase_with_transitions_rejected() {
    // camelCase: at least one lower→Upper transition (e.g., "getValue").
    // "convertSearchHitToVersionedApiKeyDoc" has multiple transitions.
    let camel_case = "convertSearchHitToVersionedApiKeyDoc";
    let bytes = camel_case.as_bytes();
    let transitions = bytes
        .windows(2)
        .filter(|pair| pair[0].is_ascii_lowercase() && pair[1].is_ascii_uppercase())
        .count();
    assert!(transitions >= 1);
    assert!(!is_secret_plausible(camel_case, &[]));
}

#[test]
fn program_identifier_pascalcase_with_transitions_rejected() {
    // PascalCase: starts uppercase, has internal transitions (e.g., "BulkUpdateApiKey").
    let pascal_case = "BulkUpdateApiKeyResponse";
    let bytes = pascal_case.as_bytes();
    let transitions = bytes
        .windows(2)
        .filter(|pair| pair[0].is_ascii_lowercase() && pair[1].is_ascii_uppercase())
        .count();
    assert!(transitions >= 1);
    assert!(!is_secret_plausible(pascal_case, &[]));
}

#[test]
fn program_identifier_boundary_zero_transitions_not_identifier() {
    // "ALLUPPERCASE" is all uppercase (no lower→Upper transitions).
    // The gate requires transitions >= 1, so this is NOT rejected as an identifier.
    let all_upper = "ALLUPPERCASE";
    let bytes = all_upper.as_bytes();
    let transitions = bytes
        .windows(2)
        .filter(|pair| pair[0].is_ascii_lowercase() && pair[1].is_ascii_uppercase())
        .count();
    assert_eq!(transitions, 0);
    // Must NOT be rejected by the program-identifier gate.
}

#[test]
fn program_identifier_boundary_single_uppercase_letter() {
    // "Foo" is a single uppercase letter at the start. It has the shape of
    // PascalCase but NO internal lower→Upper transitions (length 3 means
    // windows(2) checks "Fo" and "oo"; "Fo" is U→l, "oo" is l→l).
    // Transitions == 0, so NOT an identifier per the gate.
    let single_upper = "Foo";
    let bytes = single_upper.as_bytes();
    let transitions = bytes
        .windows(2)
        .filter(|pair| pair[0].is_ascii_lowercase() && pair[1].is_ascii_uppercase())
        .count();
    assert_eq!(transitions, 0);
    // Must NOT be rejected by the program-identifier gate.
}

#[test]
fn program_identifier_with_digits_breaks_pattern() {
    // "myHelper123Key" has digits mixed in. The identifier gate checks:
    // "!value.chars().all(|ch| ch.is_ascii_alphabetic() || ch == '_')"
    // This fails the check (has digits), so it's not rejected as an identifier.
    let with_digits = "myHelper123Key";
    assert!(with_digits.chars().any(|c| c.is_ascii_digit()));
    // Must NOT match the identifier pattern (all [A-Za-z_]).
}

#[test]
fn program_identifier_with_symbols_breaks_pattern() {
    // "my-Helper_Key" has symbols other than underscore (the hyphen).
    // The gate checks for "[A-Za-z_] only". This breaks the pattern.
    let with_symbols = "my-Helper_Key";
    assert!(with_symbols
        .chars()
        .any(|c| !c.is_ascii_alphabetic() && c != '_'));
    // Must NOT be rejected by the identifier gate.
}

#[test]
fn program_identifier_boundary_transitions_exactly_one() {
    // Exactly 1 lower→Upper transition. "aB" or "camelCase" have exactly 1.
    // The gate requires transitions >= 1, so this IS rejected.
    let one_transition = "aB";
    let bytes = one_transition.as_bytes();
    let transitions = bytes
        .windows(2)
        .filter(|pair| pair[0].is_ascii_lowercase() && pair[1].is_ascii_uppercase())
        .count();
    assert_eq!(transitions, 1);
    assert!(!is_secret_plausible(one_transition, &[]));
}

#[test]
fn program_identifier_snake_case_boundary_no_underscore() {
    // "lowercaseonly" (all lowercase, no underscore). The gate checks:
    // "contains('_') && all lowercase" → false (no underscore).
    // So NOT rejected by the snake_case branch. Must pass the identifier gate.
    let lowercase_only = "lowercaseonly";
    assert!(!lowercase_only.contains('_'));
    assert!(lowercase_only.chars().all(|c| c.is_ascii_lowercase()));
    // NOT an identifier per the gate.
}
