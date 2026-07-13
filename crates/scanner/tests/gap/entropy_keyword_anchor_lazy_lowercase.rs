//! Regression: `keyword_is_credential_anchor` defers its `to_ascii_lowercase`
//! allocation, and the deferral changes no output (Law 6 + Law 7).
//!
//! The predicate decides whether an entropy candidate's keyword reads as a
//! strong credential anchor (admitting it past the file-extension gate). It used
//! to allocate `let lower = keyword.to_ascii_lowercase()` up front, but the
//! normalized-keyword path that runs first reads `keyword` directly and returns
//! early for credential keywords, so that allocation was wasted on the common
//! positive case. It now runs after the early-return.
//!
//! This pins both that the real outputs are unchanged (credential keywords admit,
//! the no-keyword sentinel and plain words reject) and that the allocation stays
//! deferred (source order: the early-`return true` precedes the `lower` binding).

#[cfg(feature = "entropy")]
#[test]
fn keyword_credential_anchor_outputs_unchanged_by_lazy_lowercase() {
    use keyhog_scanner::testing::keyword_is_credential_anchor_for_test as is_anchor;

    // The no-keyword sentinel hits the first early-return and never allocates.
    assert!(
        !is_anchor("none (high-entropy)"),
        "no-keyword sentinel is not an anchor"
    );

    // Credential keywords admit, via the normalized path or the
    // GENERIC_ASSIGNMENT_KEYWORDS substring path.
    assert!(is_anchor("api_key"), "api_key is a credential anchor");
    assert!(is_anchor("password"), "password is a credential anchor");
    assert!(is_anchor("token"), "token is a credential anchor");
    assert!(
        is_anchor("client_secret"),
        "client_secret is a credential anchor"
    );
    assert!(
        is_anchor("bearer"),
        "bearer is a credential anchor (explicit)"
    );

    // Non-credential keywords reach the lowercase path and reject.
    assert!(
        !is_anchor("hello"),
        "a plain word is not a credential anchor"
    );
    assert!(
        !is_anchor("qwerty"),
        "a plain word is not a credential anchor"
    );

    // Optimization pin: the `to_ascii_lowercase()` allocation must be deferred
    // until AFTER the normalized-keyword early-return, so a credential keyword
    // resolved there never allocates the lowercase copy.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = std::fs::read_to_string(root.join("src/engine/phase2_entropy/helpers.rs"))
        .expect("source readable");
    let return_pos = src
        .find("return true;")
        .expect("normalize early-return present");
    let lower_pos = src
        .find("let lower = keyword.to_ascii_lowercase();")
        .expect("lowercase binding present");
    assert!(
        return_pos < lower_pos,
        "the to_ascii_lowercase() allocation must come after the normalize early-return (lazy alloc)"
    );
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin a handful of anchors/rejects; these SWEEP the behavioral
// contract. The lazy-lowercase is only correct if the decision is CASE-INSENSITIVE
// for every non-sentinel keyword (normalize case-folds; the fallback lowercases) 
// swept over `[A-Za-z0-9_]` inputs, which can never be the spaces/parens sentinel.
// Plus: the fixed credential keywords admit in any case, and any keyword containing
// `bearer` (any case) admits via the explicit substring branch. Traced against
// engine/phase2_entropy/helpers.rs:57. No proptest before.

#[cfg(feature = "entropy")]
mod property_tier {
    use keyhog_scanner::testing::keyword_is_credential_anchor_for_test as is_anchor;
    use proptest::prelude::*;

    /// Credential keywords proven to admit by the fixed vectors.
    const CREDENTIAL_KEYWORDS: &[&str] =
        &["api_key", "password", "token", "client_secret", "secret"];

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2_000))]

        /// CASE-INSENSITIVE: the anchor decision is identical for a keyword and its
        /// upper/lower-cased forms (the lazy-lowercase must change no output).
        #[test]
        fn anchor_decision_is_case_insensitive(kw in "[A-Za-z0-9_]{1,20}") {
            let as_is = is_anchor(&kw);
            let lower = is_anchor(&kw.to_ascii_lowercase());
            let upper = is_anchor(&kw.to_ascii_uppercase());
            prop_assert_eq!(as_is, lower);
            prop_assert_eq!(lower, upper);
        }

        /// The fixed credential keywords admit in either case.
        #[test]
        fn credential_keywords_admit_in_any_case(
            i in 0usize..CREDENTIAL_KEYWORDS.len(),
            upper in any::<bool>(),
        ) {
            let kw = CREDENTIAL_KEYWORDS[i];
            let cased = if upper { kw.to_ascii_uppercase() } else { kw.to_string() };
            prop_assert!(is_anchor(&cased));
        }

        /// Any keyword containing `bearer` (any case) admits via the explicit
        /// substring branch.
        #[test]
        fn any_bearer_substring_admits(
            pre in "[A-Za-z0-9_]{0,10}",
            post in "[A-Za-z0-9_]{0,10}",
        ) {
            let kw = format!("{pre}bearer{post}");
            prop_assert!(is_anchor(&kw));
            let upper = kw.to_ascii_uppercase();
            prop_assert!(is_anchor(&upper));
        }
    }
}
