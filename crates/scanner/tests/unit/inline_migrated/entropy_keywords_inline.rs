//! Migrated from inline entropy keyword/prose/decoy tests (KH-GAP-004).

use keyhog_scanner::testing::entropy_keywords::{
    entropy_value_looks_like_prose, is_dash_segmented_alnum_decoy, looks_like_english_prose,
    passes_secret_strength_checks,
};

// ── prose classification ──

#[test]
fn long_pure_lowercase_is_prose() {
    // Positive prose: 32-char pure lowercase is overwhelmingly a
    // joined sentence fragment / variable name run, not a credential.
    assert!(looks_like_english_prose(
        "thequickbrownfoxjumpsoverthelazydog"
    ));
}

#[test]
fn mixed_case_credential_is_not_prose() {
    // Negative twin: a real-world high-entropy credential with mixed
    // case must NOT be flagged as prose.
    assert!(!looks_like_english_prose(
        "Hk9PqRsTuVwXyZAbCdEfGhIjKlMnOpQr"
    ));
}

#[test]
fn alphanumeric_credential_is_not_prose() {
    // Negative twin: any digit in the value disqualifies it from the
    // prose classification.
    assert!(!looks_like_english_prose(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaa1234"
    ));
}

#[test]
fn short_lowercase_is_not_prose() {
    // Negative twin: short values fall under the 16-char floor.
    assert!(!looks_like_english_prose("password"));
}

#[test]
fn public_alias_is_consistent() {
    // Public re-export points at the same predicate.
    assert!(entropy_value_looks_like_prose(
        "thisismyverylongpassphraseinpurelowercase"
    ));
    assert!(!entropy_value_looks_like_prose(
        "Abcd1234EfGhIjKlMnOpQrStUvWx"
    ));
}

#[test]
fn multi_word_alphabetic_is_prose() {
    // Positive: a multi-word English fragment captured as the
    // value of a `description=` style field gets dropped as prose.
    // The entropy emit-path already drops whitespace-bearing values
    // wholesale, but Strict-mode plausibility (quoted-string path)
    // sees the same shape and must also classify it as prose.
    assert!(looks_like_english_prose(
        "this is the description of something"
    ));
    assert!(looks_like_english_prose("Session opened with handle XYZ"));
}

#[test]
fn multi_token_mixed_high_entropy_is_not_prose() {
    // Negative twin: a multi-token value where one token is
    // a high-entropy token (digits + mixed case) must NOT be
    // classified as prose - real credentials get pasted into
    // values that may carry surrounding whitespace from naive
    // shell joins, and we must not over-suppress them.
    assert!(!looks_like_english_prose("key=Hk9PqRsTuV4kYBiZ0Q1A2B3C"));
}

#[test]
fn sixteen_char_pure_lowercase_is_prose() {
    // Positive recall: lowering the floor from 24 to 16 catches
    // shorter joined-word shapes that the prior gate walked past.
    // `description = "configurationhelper"` would surface as a
    // generic-secret/entropy candidate without this.
    assert!(looks_like_english_prose("configurationmgr"));
}

#[test]
fn fifteen_char_pure_lowercase_is_not_prose() {
    // Negative twin: just below the floor stays admitted.
    assert!(!looks_like_english_prose("configurationm"));
}

// ── strict-secret / decoy gating ──

#[test]
fn symbolic_password_in_credential_context_admitted() {
    // Positive recall: a real-world symbolic password whose Shannon
    // entropy lands in the 3.5-4.5 band (below the blanket high-
    // entropy floor) gets admitted when the value sits in a
    // credential-keyword anchored context. Catches the FN class
    // described in the generic-password investigator findings
    // (Y6NPMwS*rWGUv!JQnSG6a#D14, 1E1B3b4Ho$U4kYBi, etc.).
    assert!(passes_secret_strength_checks("1E1B3b4Ho$U4kYBi", true,));
    assert!(passes_secret_strength_checks(
        "Y6NPMwS*rWGUv!JQnSG6a#D14",
        true,
    ));
}

#[test]
fn pure_alnum_low_entropy_in_credential_context_rejected() {
    // Negative twin: a pure-alphanumeric value with sub-4.5 entropy
    // and NO symbol stays rejected even in credential context - the
    // anchor + symbol-set combo is what lifts the floor; alphanumeric
    // alone is indistinguishable from CamelCase identifiers.
    assert!(!passes_secret_strength_checks("abcdefghij1234567", true,));
}

#[test]
fn symbolic_value_no_anchor_keeps_high_floor() {
    // Negative twin: outside credential context, the relaxation
    // does not apply - a symbolic 3.5-4.5 entropy value alone is
    // not enough signal without the keyword anchor.
    // `H!l$o-w0rld-pas` has symbols and ~3.7 entropy, below the
    // 4.5 blanket floor, with no anchor - must stay rejected.
    assert!(!passes_secret_strength_checks("H!l$o-w0rld-pas", false,));
}

#[test]
fn english_prose_with_anchor_still_rejected() {
    // Adversarial: a credential-anchored value that happens to be
    // English prose stays rejected - the prose-shape filter at
    // higher emit-path tiers catches this, but the strict checker
    // also gates on entropy floors which prose fails.
    // `passwordispasswordispassword` is pure-lowercase 28 chars,
    // entropy lands around 3.0 - both alnum-only branches reject.
    assert!(!passes_secret_strength_checks(
        "passwordispasswordispassword",
        true,
    ));
}

#[test]
fn dash_segmented_alnum_decoys_rejected() {
    // Negative twin (the 42-FP class from the 0f05b3de mirror):
    // license/product serials, template placeholders and segmented
    // identifiers are dash-joined alnum runs. The license-serial
    // shape measures ~4.58 entropy - ABOVE the 4.5 blanket floor -
    // so it would otherwise be admitted unconditionally. Every entry
    // in this corpus must stay rejected, including in credential
    // context where the relaxed floor is widest.
    let decoy_corpus = [
        "A1B2C-D3E4F-G5H6I-J7K8L-M9N0P", // mixed 5x5 license serial
        "ABCDE-FGHIJ-KLMNO-PQRST-UVWXY", // alpha 5x5 license serial
        "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX", // template placeholder serial
        "00000-00000-00000-00000-00000", // zero-filled serial
        "my-service-prod-key-name-here", // segmented identifier
    ];
    let fp: usize = decoy_corpus
        .iter()
        .filter(|value| passes_secret_strength_checks(value, true))
        .count();
    assert_eq!(fp, 0, "license/template decoys must yield zero admits");
    // And outside credential context too.
    assert!(decoy_corpus
        .iter()
        .all(|value| !passes_secret_strength_checks(value, false)));
}

#[test]
fn symbolic_password_class_survives_decoy_gate() {
    // Positive twin: the symbolic-password recall must be intact after
    // the dash-segmented decoy gate. These carry symbol classes beyond
    // `-` ($ * ! #), never reduce to dash-segmented alnum, and stay
    // admitted in credential context.
    let passwords = [
        "Y6NPMwS*rWGUv!JQnSG6a#D14",
        "1E1B3b4Ho$U4kYBi",
        "sk-proj-AbC9$xZ", // hyphen present but a `$` defeats the decoy shape
    ];
    assert!(passwords
        .iter()
        .all(|value| passes_secret_strength_checks(value, true)));
}

#[test]
fn random_dash_segmented_tokens_survive_decoy_gate() {
    for secret in [
        "Kp4Qx7-Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn",
        "ZAOruHaF3QjNZzFWmvWmil-gzx1rVJEJumWonOs0RTNf54QVHP3cn8fLFtV5iTuy8ymH2Cn0RnV2ho2aJn7ADtc7ltW",
        "S4oxj2N-bVEi6ivQsrW3",
    ] {
        assert!(
            !is_dash_segmented_alnum_decoy(secret),
            "random dash-bearing token must not be classified as a serial decoy: {secret}"
        );
    }
}

#[test]
fn dash_segmented_helper_excludes_symbolic_and_unsegmented() {
    // Unit check on the shape predicate itself: only pure
    // dash-joined alnum runs qualify; richer symbol sets and
    // dash-free values do not.
    assert!(is_dash_segmented_alnum_decoy("A1B2C-D3E4F-G5H6I"));
    assert!(!is_dash_segmented_alnum_decoy("Y6NPMwS*rWGUv!JQ")); // symbols, no dash
    assert!(!is_dash_segmented_alnum_decoy("sk-proj-AbC9$xZ")); // dash but `$` present
    assert!(!is_dash_segmented_alnum_decoy("nodashvalue1234")); // no dash at all
    assert!(!is_dash_segmented_alnum_decoy("-leading-dash")); // empty leading group
    assert!(!is_dash_segmented_alnum_decoy("trailing-dash-")); // empty trailing group
}
