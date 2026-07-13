//! Precision regression for the structural-password-slot family masks.
//!
//! The `url-credentials` / `sql-password` / `cli-password-flag` detectors are
//! strong-anchor AND `is_service_anchored`, so the suppression pipeline sets
//! `bypass_shape_gates = true` and SKIPS the Tier-B repetitive-run / repeated-
//! block mask gates that normally drop a redaction mask. `is_confident_dictionary_word`
//! cannot catch a mask: `xxxxxxxx` / `12345678` have improbable English bigrams,
//! so the model is (correctly) NOT confident they are words, so without a second
//! guard the strong anchor surfaces every `--password xxxxxxxx` / `IDENTIFIED BY
//! 'XXXXXXXX'` redaction as a false positive.
//!
//! The `has_low_letter_diversity` guard (distinct letters < MIN_DISTINCT_LETTERS,
//! the SAME floor `is_random_token` uses) closes that: a single-char / alternating
//! / digit-only mask has < 3 distinct letters and is dropped, while a genuine short
//! random password (`i8cr1w!`, 4 distinct letters) clears the floor and is kept.
//!
//! Found by dogfooding the family generalization (task #54): the strong-anchor
//! change recovered random passwords but regressed the mask class that weak-anchor
//! used to suppress via the (now-skipped) Tier-B gates. Each assertion checks the
//! exact surfaced (or absent) credential bytes via the on-disk scanner.

mod support;
use support::contracts::{make_chunk, scanner};

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;

const FAMILY: [&str; 3] = ["url-credentials", "sql-password", "cli-password-flag"];

fn matches(s: &CompiledScanner, chunk: &Chunk) -> Vec<(String, String)> {
    s.clear_fragment_cache();
    s.scan(chunk)
        .into_iter()
        .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
        .collect()
}

/// True iff ANY structural-password-slot detector surfaces `credential`.
fn family_surfaces(text: &str, credential: &str) -> bool {
    let s = scanner();
    let chunk = make_chunk(text, "source", "probe.txt");
    matches(&s, &chunk)
        .iter()
        .any(|(id, cred)| FAMILY.contains(&id.as_str()) && cred == credential)
}

/// True iff `credential` surfaces under exactly `detector_id`.
fn surfaces_under(text: &str, detector_id: &str, credential: &str) -> bool {
    let s = scanner();
    let chunk = make_chunk(text, "source", "probe.txt");
    matches(&s, &chunk)
        .iter()
        .any(|(id, cred)| id == detector_id && cred == credential)
}

// ── MASKS the strong anchor must DROP (the regression) ──────────────────────
//
// Each is a value the Tier-B repetitive-run gate would have caught under a weak
// anchor; the family skips that gate, so `has_low_letter_diversity` must catch it.

#[test]
fn url_single_char_mask_suppressed() {
    assert!(
        !family_surfaces("ftp://deploy:xxxxxxxx@db.internal/data", "xxxxxxxx"),
        "a single-letter URL userinfo mask (1 distinct letter) must be dropped"
    );
}

#[test]
fn sql_single_char_mask_suppressed() {
    assert!(
        !family_surfaces("CREATE USER 'svc' IDENTIFIED BY 'xxxxxxxx';", "xxxxxxxx"),
        "a single-letter IDENTIFIED BY mask must be dropped"
    );
}

#[test]
fn cli_single_char_mask_suppressed() {
    assert!(
        !family_surfaces("deploy --password xxxxxxxx", "xxxxxxxx"),
        "a single-letter --password mask must be dropped"
    );
}

#[test]
fn url_repeated_letter_mask_suppressed() {
    assert!(
        !family_surfaces("ftp://svc:aaaaaa@host.example/x", "aaaaaa"),
        "a 6-char repeated-letter URL mask (1 distinct letter) must be dropped"
    );
}

#[test]
fn sql_uppercase_mask_suppressed() {
    assert!(
        !family_surfaces("ALTER USER app IDENTIFIED BY 'XXXXXXXX';", "XXXXXXXX"),
        "an upper-case single-letter IDENTIFIED BY mask must be dropped"
    );
}

#[test]
fn cli_uppercase_mask_suppressed() {
    assert!(
        !family_surfaces("svc --password XXXXXXXX", "XXXXXXXX"),
        "an upper-case single-letter --password mask must be dropped"
    );
}

#[test]
fn url_alternating_two_letter_mask_suppressed() {
    assert!(
        !family_surfaces("ftp://svc:ababab@host.example/x", "ababab"),
        "an alternating 2-distinct-letter URL mask must be dropped"
    );
}

#[test]
fn sql_alternating_two_letter_mask_suppressed() {
    assert!(
        !family_surfaces("CREATE USER 'svc' IDENTIFIED BY 'ababab';", "ababab"),
        "an alternating 2-distinct-letter IDENTIFIED BY mask must be dropped"
    );
}

#[test]
fn cli_alternating_two_letter_mask_suppressed() {
    assert!(
        !family_surfaces("svc --password xyxyxyxy", "xyxyxyxy"),
        "an alternating 2-distinct-letter --password mask must be dropped"
    );
}

#[test]
fn url_digit_only_value_suppressed() {
    assert!(
        !family_surfaces("ftp://svc:12345678@host.example/x", "12345678"),
        "a pure-digit URL userinfo value (0 distinct letters) must be dropped"
    );
}

#[test]
fn sql_digit_only_value_suppressed() {
    assert!(
        !family_surfaces("CREATE USER 'svc' IDENTIFIED BY '12345678';", "12345678"),
        "a pure-digit IDENTIFIED BY value (0 distinct letters) must be dropped"
    );
}

#[test]
fn cli_digit_only_value_suppressed() {
    assert!(
        !family_surfaces("svc --password 12345678", "12345678"),
        "a pure-digit --password value (0 distinct letters) must be dropped"
    );
}

#[test]
fn cli_repeated_zero_mask_suppressed() {
    assert!(
        !family_surfaces("svc --password 00000000", "00000000"),
        "a repeated-zero --password mask must be dropped"
    );
}

// ── RECALL the family must KEEP, genuine random passwords (≥3 distinct) ─────

#[test]
fn url_random_password_still_surfaces() {
    assert!(
        surfaces_under(
            "ftp://deploy:pxidztpv@db.internal/data",
            "url-credentials",
            "pxidztpv"
        ),
        "a random lowercase URL userinfo password (8 distinct letters) must STILL surface"
    );
}

#[test]
fn sql_random_password_still_surfaces() {
    assert!(
        surfaces_under(
            "CREATE USER 'svc'@'localhost' IDENTIFIED BY 'argriyjqr';",
            "sql-password",
            "argriyjqr"
        ),
        "a random lowercase IDENTIFIED BY password must STILL surface"
    );
}

#[test]
fn cli_low_alpha_password_still_surfaces() {
    // `i8cr1w!` has 4 distinct letters (i,c,r,w), clears the diversity floor
    // and < 6 alpha (the bigram model returns None), so it is neither a confident
    // dictionary word nor a low-diversity mask: the recovery the fix must preserve.
    assert!(
        surfaces_under(
            "nats server raft step-down --password i8cr1w!",
            "cli-password-flag",
            "i8cr1w!"
        ),
        "a 4-distinct-letter low-alpha --password value must STILL surface"
    );
}

#[test]
fn cli_long_mixed_random_still_surfaces() {
    assert!(
        surfaces_under(
            "mysqldump --passwd=Qx7Kp2Vn9Rm4Lt8w db",
            "cli-password-flag",
            "Qx7Kp2Vn9Rm4Lt8w"
        ),
        "a long mixed-case random --passwd value must STILL surface"
    );
}

#[test]
fn boundary_exactly_three_distinct_letters_surfaces() {
    // MIN_DISTINCT_LETTERS = 3 is the KEEP floor (the predicate is strict `<`), so
    // a value with EXACTLY 3 distinct letters clears it and surfaces. `vkx7vkx`
    // has letters v,k,x (3 distinct) and is not a confident dictionary word.
    assert!(
        family_surfaces("svc --password vkx7vkx", "vkx7vkx"),
        "a value with exactly 3 distinct letters is above the floor and must surface"
    );
}

// ── DICTIONARY placeholders the EXISTING gate must STILL drop (no regression) ─

#[test]
fn cli_dictionary_word_still_suppressed() {
    assert!(
        !family_surfaces("deploy --password password", "password"),
        "the literal word `password` must STAY suppressed by the dictionary gate"
    );
}

#[test]
fn sql_dictionary_word_still_suppressed() {
    assert!(
        !family_surfaces("ALTER USER app IDENTIFIED BY 'secret';", "secret"),
        "the literal word `secret` must STAY suppressed by the dictionary gate"
    );
}

#[test]
fn url_dictionary_word_still_suppressed() {
    assert!(
        !family_surfaces("ftp://svc:welcome@host.example/x", "welcome"),
        "the literal word `welcome` must STAY suppressed by the dictionary gate"
    );
}
