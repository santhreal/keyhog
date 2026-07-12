//! Unit tests for the random-token vs dictionary-identifier discriminator
//! (`src/suppression/token_randomness.rs`, KH-L-0413/0414).
//!
//! Migrated out of the source file to satisfy the no-inline-tests-in-`src`
//! policy (`tests/gap/no_inline_tests_in_src.rs`). The module is mounted into
//! the lib test build via `src/lib.rs`'s `#[cfg(test)] mod unit`, so the
//! `pub(crate)` predicates, constants, and types are all reachable here.

use keyhog_scanner::suppression::token_randomness::{
    has_low_letter_diversity, is_confident_dictionary_word, is_random_token,
    keep_identifier_gate_with_randomness, keep_word_separated_gate_with_randomness,
    RandomTokenEvidence, TokenRandomness, MIN_ALPHA, MIN_DISTINCT_LETTERS,
};

// ── is_confident_dictionary_word: confident English words ⇒ true ───────

#[test]
fn password_is_confident_dictionary_word() {
    assert!(is_confident_dictionary_word("password"));
}

#[test]
fn secret_six_chars_is_confident_dictionary_word() {
    // Exactly MIN_ALPHA chars — the model is evaluated and `secret` reads
    // as English, so it is confidently a dictionary word.
    assert_eq!("secret".len(), MIN_ALPHA);
    assert!(is_confident_dictionary_word("secret"));
}

#[test]
fn welcome_is_confident_dictionary_word() {
    assert!(is_confident_dictionary_word("welcome"));
}

#[test]
fn username_is_confident_dictionary_word() {
    assert!(is_confident_dictionary_word("username"));
}

// ── random tokens ⇒ false (kept) ───────────────────────────────────────

#[test]
fn lowercase_random_token_is_not_dictionary_word() {
    // The exact CredData userinfo passwords the strong anchor must recover.
    for token in ["pxidztpv", "zavvfuco", "vvaitgiz", "nxruoapftabufvcsa"] {
        assert!(
            !is_confident_dictionary_word(token),
            "{token} is a random token, not a confident dictionary word"
        );
        assert!(
            is_random_token(token),
            "{token} must read as a random token"
        );
    }
}

#[test]
fn six_char_random_token_is_not_dictionary_word() {
    // `hjxzyi` is exactly MIN_ALPHA chars and scores BELOW the English
    // threshold — random, not dictionary, so it is kept.
    assert!(!is_confident_dictionary_word("hjxzyi"));
    assert!(is_random_token("hjxzyi"));
}

#[test]
fn mixed_case_random_token_is_not_dictionary_word() {
    assert!(!is_confident_dictionary_word("Kc4mLp9Rt8Vy3Bn6"));
}

// ── short tokens (< MIN_ALPHA) ⇒ false on the FAIL-SAFE, never suppressed ─

#[test]
fn short_tokens_are_not_confident_dictionary_words() {
    // Below MIN_ALPHA the bigram model returns None: the predicate must be
    // false (it can only DROP what the model is SURE is English), so a short
    // random userinfo value is never suppressed by this gate — the regex
    // `{6,128}` floor, not this predicate, is what bounds the short case.
    for token in ["pass", "admin", "root", "user", "pwd"] {
        assert!(
            !is_confident_dictionary_word(token),
            "{token} is below MIN_ALPHA — the predicate must fail-safe to false"
        );
    }
}

#[test]
fn empty_and_nonalpha_are_not_dictionary_words() {
    assert!(!is_confident_dictionary_word(""));
    assert!(!is_confident_dictionary_word("123456"));
    assert!(!is_confident_dictionary_word("h%40co"));
}

// ── has_low_letter_diversity: repetitive / digit-only MASKS ⇒ true ─────

#[test]
fn single_letter_mask_is_low_diversity() {
    // The exact strong-anchor blind spot: `xxxxxxxx` has improbable English
    // bigrams (so it is NOT a confident dictionary word) but only ONE distinct
    // letter — a redaction mask, never a real password. The family gate must
    // drop it on this predicate, since the Tier-B repetitive-run gate is
    // skipped for the service-anchored family.
    for mask in ["xxxxxxxx", "aaaaaa", "XXXXXXXX", "00000000", "zzzzzz"] {
        assert!(
            has_low_letter_diversity(mask),
            "{mask} is a ≤1-distinct-letter mask, not a password"
        );
    }
}

#[test]
fn alternating_two_letter_mask_is_low_diversity() {
    // `ababab` / `xyxyxy` have exactly 2 distinct letters — below the floor of
    // 3 — so they are alternating patterns, not random passwords.
    for mask in ["ababab", "xyxyxyxy", "a1a1a1a1"] {
        assert!(
            has_low_letter_diversity(mask),
            "{mask} has < {MIN_DISTINCT_LETTERS} distinct letters"
        );
    }
}

#[test]
fn digit_and_symbol_only_values_are_low_diversity() {
    // Pure-digit / pure-symbol values have ZERO distinct letters — a sequence
    // or punctuation run in a password slot, dropped by the diversity floor.
    for mask in ["12345678", "00000000", "!@#$%^&*", "--------"] {
        assert!(
            has_low_letter_diversity(mask),
            "{mask} has zero distinct letters and must be low-diversity"
        );
    }
}

#[test]
fn genuine_random_passwords_clear_the_diversity_floor() {
    // The recall the family must KEEP: a real short/low-alpha password has ≥ 3
    // distinct letters and must NOT be flagged as a low-diversity mask.
    for pw in [
        "i8cr1w!",          // 4 distinct letters (i,c,r,w) — the recovery case
        "pxidztpv",         // userinfo random
        "argriyjqr",        // SQL IDENTIFIED BY random
        "Rcuhxw1486",       // PowerShell -Password random
        "Qx7Kp2Vn9Rm4Lt8w", // long mixed random
    ] {
        assert!(
            !has_low_letter_diversity(pw),
            "{pw} has ≥ {MIN_DISTINCT_LETTERS} distinct letters — a real password, not a mask"
        );
    }
}

#[test]
fn exactly_three_distinct_letters_is_not_low_diversity() {
    // Boundary: MIN_DISTINCT_LETTERS = 3 is the KEEP floor, so a value with
    // exactly 3 distinct letters clears it (the predicate is strict `<`).
    assert_eq!(MIN_DISTINCT_LETTERS, 3);
    assert!(!has_low_letter_diversity("abcabc")); // a,b,c = 3 distinct
    assert!(has_low_letter_diversity("abab")); //   a,b   = 2 distinct
}

#[test]
fn hex_digests_are_not_dictionary_words() {
    // The exact ripple cause: a pure-hex key's `a..f` adjacencies (`ab`,
    // `be`, `de`, `ea`) read as probable English, but a hex digest carries
    // NO `g..z` letter, so the predicate must reject it — otherwise the
    // placeholder gate would suppress real hex secrets (rollbar/steam/…).
    for hex in [
        "08c0fee0abeb7224113fd958de7528ab",
        "24ed7c1290d4ed5e45bd69c30994238c",
        "533b30a72eee83f00d7436071027b88f",
        "deadbeefcafebabe",
    ] {
        assert!(
            !is_confident_dictionary_word(hex),
            "{hex} is a hex digest (no g..z letter), not a dictionary word"
        );
    }
}

// ── RandomTokenEvidence: the analyzer the predicates share ──────────────

#[test]
fn evidence_counts_distinct_letters_case_insensitively() {
    // `aAbBcC` folds to three distinct letters; the diversity floor sees 3.
    assert_eq!(RandomTokenEvidence::analyze("aAbBcC").distinct_letters(), 3);
    assert_eq!(RandomTokenEvidence::analyze("aabbcc").distinct_letters(), 3);
    assert_eq!(
        RandomTokenEvidence::analyze("xxxxxxxx").distinct_letters(),
        1
    );
    assert_eq!(
        RandomTokenEvidence::analyze("12345678").distinct_letters(),
        0
    );
}

#[test]
fn evidence_mean_bigram_logprob_is_none_below_min_alpha() {
    // Fewer than MIN_ALPHA alphabetic chars ⇒ the model abstains (None), the
    // fail-safe that keeps the predicates from judging a too-short token.
    assert_eq!("abcde".len(), MIN_ALPHA - 1);
    assert!(RandomTokenEvidence::analyze("abcde")
        .mean_bigram_logprob()
        .is_none());
    // Digits break the alphabetic run, so they do not count toward MIN_ALPHA.
    assert!(RandomTokenEvidence::analyze("a1b2c3")
        .mean_bigram_logprob()
        .is_none());
}

#[test]
fn evidence_mean_bigram_logprob_is_some_at_min_alpha() {
    // At MIN_ALPHA contiguous letters the model produces a score.
    assert_eq!("secret".len(), MIN_ALPHA);
    assert!(RandomTokenEvidence::analyze("secret")
        .mean_bigram_logprob()
        .is_some());
}

#[test]
fn evidence_random_and_dictionary_scores_straddle_the_threshold() {
    // The discriminator is sound only if a random token scores strictly below a
    // dictionary word; assert the ordering directly on the model output.
    let random = RandomTokenEvidence::analyze("pxidztpv")
        .mean_bigram_logprob()
        .expect("8 alpha chars ⇒ scored");
    let english = RandomTokenEvidence::analyze("password")
        .mean_bigram_logprob()
        .expect("8 alpha chars ⇒ scored");
    assert!(
        random < english,
        "random token {random} must score below dictionary word {english}"
    );
}

// ── is_random_token: dictionary words are NOT random ────────────────────

#[test]
fn dictionary_words_are_not_random_tokens() {
    // The mirror of the recall cases: a pronounceable English word must NOT be
    // treated as a random token, or the identifier gates would lift real code
    // references back into findings.
    for word in ["password", "username", "welcome"] {
        assert!(
            !is_random_token(word),
            "{word} is English, not a random token"
        );
    }
}

// ── TokenRandomness: cached evidence agrees with the direct predicate ────

#[test]
fn token_randomness_cached_verdict_matches_direct_predicate() {
    // for_candidate precomputes evidence for the candidate; querying that exact
    // value must return the cached verdict, and querying a DIFFERENT value must
    // recompute — both agreeing byte-for-byte with the free `is_random_token`.
    let randomness = TokenRandomness::for_candidate("pxidztpv");
    assert_eq!(
        randomness.is_random_token("pxidztpv"),
        is_random_token("pxidztpv")
    );
    assert!(randomness.is_random_token("pxidztpv"));
    // Different value ⇒ recomputed path, still correct.
    assert_eq!(
        randomness.is_random_token("password"),
        is_random_token("password")
    );
    assert!(!randomness.is_random_token("password"));
}

// ── keep_identifier_gate_with_randomness: contiguous gate ───────────────

#[test]
fn identifier_gate_lifts_random_token_keeps_dictionary() {
    // The gate stays engaged (true ⇒ suppressed) for a dictionary identifier and
    // lifts (false ⇒ recovered) for a random token — a thin wrapper over
    // `!is_random_token`, the single source of truth both call sites share.
    let random = TokenRandomness::for_candidate("pxidztpv");
    assert!(
        !keep_identifier_gate_with_randomness("pxidztpv", &random),
        "a random token must lift the identifier gate"
    );
    let dictionary = TokenRandomness::for_candidate("password");
    assert!(
        keep_identifier_gate_with_randomness("password", &dictionary),
        "a dictionary identifier must keep the gate engaged"
    );
}

// ── keep_word_separated_gate_with_randomness: stricter sibling ──────────

#[test]
fn word_separated_gate_keeps_digit_or_uppercase_bearing_values() {
    // Any digit / uppercase / non-ASCII byte ⇒ NOT the clean lowercase password
    // shape ⇒ keep the gate engaged WITHOUT consulting the model (the acronym /
    // product-key class the English model would otherwise mis-lift).
    for identifier in ["d2i_PKCS7_bio", "sqlite3_malloc64", "2iw9-n01w-Mc4V-faEC"] {
        let r = TokenRandomness::for_candidate(identifier);
        assert!(
            keep_word_separated_gate_with_randomness(identifier, &r),
            "{identifier} has digits/uppercase ⇒ gate must stay engaged"
        );
    }
}

#[test]
fn word_separated_gate_lifts_all_lowercase_random_token() {
    // A clean all-lowercase random token passes the shape check and is lifted on
    // the randomness verdict.
    let r = TokenRandomness::for_candidate("pxidztpv");
    assert!(
        !keep_word_separated_gate_with_randomness("pxidztpv", &r),
        "an all-lowercase random token must lift the word-separated gate"
    );
}

#[test]
fn word_separated_gate_keeps_lowercase_dictionary_word() {
    // All-lowercase but pronounceable ⇒ passes the shape check, but the model
    // says it is English, so the gate stays engaged (true ⇒ suppressed).
    let r = TokenRandomness::for_candidate("password");
    assert!(
        keep_word_separated_gate_with_randomness("password", &r),
        "a lowercase dictionary word must keep the word-separated gate engaged"
    );
}
