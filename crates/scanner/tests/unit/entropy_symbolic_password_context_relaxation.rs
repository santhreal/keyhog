//! Boundary test for symbolic-password entropy relaxation in credential context
//! (keywords.rs:376-398).
//!
//! Real passwords with symbols ($, *, !, #, etc.) can have entropy as low as 3.5
//! bits/byte while still being valid credentials. Outside a credential-keyword
//! anchor, the baseline HIGH_ENTROPY_THRESHOLD (4.5) applies. Inside one, symbolic
//! passwords are admitted at 3.5 threshold. Pure alphanumeric values keep 4.5
//! regardless of context.

use keyhog_scanner::entropy::shannon_entropy;
use keyhog_scanner::testing::entropy_keywords::is_secret_plausible_in_context;

#[test]
fn symbolic_password_3_5_with_context_accepted() {
    // "Y6NPMwS*rWGUv!JQnSG6a#D14" has entropy ~4.1 bits and contains symbols.
    // Inside credential context, it's admitted at 3.5 floor. Must pass.
    let symbolic_pwd = "Y6NPMwS*rWGUv!JQnSG6a#D14";
    let entropy = shannon_entropy(symbolic_pwd.as_bytes());
    assert!(entropy >= 3.5 && entropy < 4.5, "entropy: {}", entropy);
    assert!(symbolic_pwd.bytes().any(|b| !b.is_ascii_alphanumeric()));
    // In credential context (is_credential_context = true), should be accepted
    // at the 3.5 floor.
    let placeholder_keywords = vec![];
    assert!(is_secret_plausible_in_context(
        symbolic_pwd,
        &placeholder_keywords,
        true,
        false
    ));
}

#[test]
fn symbolic_password_3_5_without_context_rejected() {
    // Same symbolic password, but outside credential context.
    // It must be rejected because entropy < 4.5 (the baseline).
    let symbolic_pwd = "Y6NPMwS*rWGUv!JQnSG6a#D14";
    let entropy = shannon_entropy(symbolic_pwd.as_bytes());
    assert!(entropy >= 3.5 && entropy < 4.5, "entropy: {}", entropy);
    assert!(symbolic_pwd.bytes().any(|b| !b.is_ascii_alphanumeric()));
    // Outside credential context, rejected because entropy < 4.5.
    let placeholder_keywords = vec![];
    assert!(!is_secret_plausible_in_context(
        symbolic_pwd,
        &placeholder_keywords,
        false,
        false
    ));
}

#[test]
fn pure_alphanumeric_3_5_with_context_still_rejected() {
    // Pure alphanumeric 3.5-4.5 entropy below the mixed-alnum length carve-out
    // is rejected. The 3.5 symbolic relaxation applies only when a symbol is
    // present.
    let alphanumeric = "abc123def456ghi789j";
    let entropy = shannon_entropy(alphanumeric.as_bytes());
    assert!(entropy >= 3.5 && entropy < 4.5, "entropy: {}", entropy);
    assert!(alphanumeric.bytes().all(|b| b.is_ascii_alphanumeric()));
    // Even with credential context, no symbol → no relaxation.
    let placeholder_keywords = vec![];
    assert!(!is_secret_plausible_in_context(
        alphanumeric,
        &placeholder_keywords,
        true,
        false
    ));
}

#[test]
fn symbolic_password_boundary_3_5_exact_entropy() {
    // Build a string with entropy as close to 3.5 as possible.
    // Shannon entropy is p·log2(p) summed over all bytes. For a targeted
    // entropy, we need to construct a specific byte distribution.
    // For simplicity, use "1E1B3b4Ho$U4kYBi" which has entropy ~3.95 (from the code comment).
    let borderline = "1E1B3b4Ho$U4kYBi";
    let entropy = shannon_entropy(borderline.as_bytes());
    assert!(entropy > 3.5 && entropy < 4.5, "entropy: {}", entropy);
    assert!(borderline.bytes().any(|b| !b.is_ascii_alphanumeric()));
    // With credential context, should be accepted.
    let placeholder_keywords = vec![];
    assert!(is_secret_plausible_in_context(
        borderline,
        &placeholder_keywords,
        true,
        false
    ));
}

#[test]
fn symbolic_password_with_single_symbol_relaxation_applies() {
    // Must have "at least one symbolic (non-alphanumeric) character".
    // Even a single symbol should trigger the relaxation.
    let almost_alnum = "abc123def456ghi789jk*";
    assert_eq!(
        almost_alnum
            .chars()
            .filter(|c| !c.is_ascii_alphanumeric())
            .count(),
        1
    );
    let entropy = shannon_entropy(almost_alnum.as_bytes());
    // If entropy >= 3.5 and has a symbol, it should pass with credential context.
    let placeholder_keywords = vec![];
    if entropy >= 3.5 && entropy < 4.5 {
        assert!(is_secret_plausible_in_context(
            almost_alnum,
            &placeholder_keywords,
            true,
            false
        ));
    }
}

#[test]
fn symbolic_password_multiple_symbols_entropy_relaxation() {
    // Multiple symbols with enough alphanumeric mass should pass in credential
    // context once entropy reaches the symbolic relaxation floor.
    let multi_symbol = "P@ssw0rd!AbC123$";
    let entropy = shannon_entropy(multi_symbol.as_bytes());
    assert!(multi_symbol.bytes().any(|b| !b.is_ascii_alphanumeric()));
    // In credential context, admitted if entropy >= 3.5.
    let placeholder_keywords = vec![];
    if entropy >= 3.5 {
        assert!(is_secret_plausible_in_context(
            multi_symbol,
            &placeholder_keywords,
            true,
            false
        ));
    }
}

#[test]
fn pure_alphanumeric_4_5_accepted_without_context() {
    // Pure alphanumeric >= 4.5 is accepted regardless of context.
    // This is the default entropy floor.
    let high_entropy_alnum = "Xk7mP2qL9wR5tY8uI0oAs3Dg";
    assert!(high_entropy_alnum
        .bytes()
        .all(|b| b.is_ascii_alphanumeric()));
    let entropy = shannon_entropy(high_entropy_alnum.as_bytes());
    assert!(entropy >= 4.5, "entropy: {}", entropy);
    // Accepted even without credential context.
    let placeholder_keywords = vec![];
    assert!(is_secret_plausible_in_context(
        high_entropy_alnum,
        &placeholder_keywords,
        false,
        false
    ));
}

#[test]
fn symbolic_password_no_symbols_detected_fails_relaxation() {
    // If the value has no symbols but was somehow marked as symbolic,
    // the gate should not apply relaxation. Verify: bytes.any(|b| !b.is_ascii_alphanumeric()).
    let pure_alnum = "abc123def456ghi789";
    assert!(!pure_alnum.bytes().any(|b| !b.is_ascii_alphanumeric()));
    let entropy = shannon_entropy(pure_alnum.as_bytes());
    if entropy >= 3.5 && entropy < 4.5 {
        // Even with credential context, should be rejected (no symbols).
        let placeholder_keywords = vec![];
        assert!(!is_secret_plausible_in_context(
            pure_alnum,
            &placeholder_keywords,
            true,
            false
        ));
    }
}

#[test]
fn context_true_requires_symbol_for_relaxation() {
    // The relaxation is: "is_credential_context && has_symbol && entropy >= 3.5"
    // All three must be true. If any is false, the 4.5 floor applies.
    // Already tested above, but summarize:
    // - context=true, symbol=yes, entropy=3.7 → PASS
    // - context=true, symbol=no,  entropy=3.7 → FAIL (no symbol)
    // - context=false, symbol=yes, entropy=3.7 → FAIL (no context)
    // - context=false, symbol=no,  entropy=3.7 → FAIL (both)
}
