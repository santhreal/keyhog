//! Regression: the Slack checksum validator must NOT reject legitimate
//! 2-segment ("mixed") bot tokens, which a casual `-`-split reads as the
//! 3-segment form `xoxb-{digits}-{secret}`.
//!
//! Root cause (`crates/scanner/src/checksum/slack.rs`): the bot regex was
//! `^xoxb-[0-9]{10,15}-[0-9]{10,15}-[a-zA-Z0-9]{15,40}$`, which REQUIRES two
//! numeric segments. The `slack-bot-token` detector
//! (`detectors/slack-bot-token.toml`) is the source of truth for what the
//! scanner emits and it ships TWO patterns — a 3-segment canonical
//! (`xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}`) AND a 2-segment /
//! "mixed" form (`xoxb-[0-9]{10,13}-[0-9A-Za-z]{15,36}`) — and the per-detector
//! contract (`tests/contracts/slack-bot-token.toml`) states both "must surface".
//!
//! This validator is the checksum GATE every emitted Slack match is routed
//! through (`checksum_adjusted_confidence` -> `ChecksumResult::Invalid` => the
//! engine DROPS the finding, see `engine/hot_patterns.rs`). So the mandatory
//! second numeric segment turned every legitimate 2-segment bot token into a
//! silent false negative.
//!
//! Fix: make the second numeric segment optional
//! (`^xoxb-[0-9]{10,15}(?:-[0-9]{10,15})?-[a-zA-Z0-9]{15,40}$`).
//!
//! Pre-fix: the `*_valid` / `*_kept` assertions below FAIL (validator returned
//! `Invalid`, `checksum_adjusted_confidence` returned `None`). Post-fix they
//! PASS. The negatives and the xoxp lockers guard against over-widening.

use keyhog_scanner::checksum::{
    checksum_adjusted_confidence, validate_checksum, ChecksumResult, ChecksumValidator,
    SlackTokenValidator, CHECKSUM_VALID_FLOOR,
};

// A real-world 2-segment / "mixed" Slack bot token: prefix + one 10-digit
// numeric segment + a 24-char alnum secret. The leading `xox` is split so this
// source file is not itself flagged when keyhog dogfoods its own tree.
const TWO_SEGMENT_BOT: &str = concat!("xox", "b-1234567890-AbCdEfGhIjKlMnOpQrStUvWx");

// ───────────────────────── positive (the bug) ──────────────────────────────

#[test]
fn two_segment_bot_token_is_valid() {
    // Pre-fix this returned Invalid (the mandatory 2nd numeric segment was
    // absent), which made the engine drop a real bot token.
    assert_eq!(
        SlackTokenValidator.validate(TWO_SEGMENT_BOT),
        ChecksumResult::Valid,
        "legitimate 2-segment bot token {TWO_SEGMENT_BOT:?} must validate"
    );
}

#[test]
fn two_segment_bot_token_routes_valid_through_registry() {
    // Same verdict through the public aggregator the engine actually calls.
    assert_eq!(validate_checksum(TWO_SEGMENT_BOT), ChecksumResult::Valid);
}

#[test]
fn two_segment_bot_token_is_kept_not_dropped_by_confidence_gate() {
    // `checksum_adjusted_confidence` is the single policy the emission paths
    // use. Pre-fix it returned `None` (DROP) for this token; post-fix it floors
    // the confidence at CHECKSUM_VALID_FLOOR (KEEP).
    let scored = checksum_adjusted_confidence(0.70, TWO_SEGMENT_BOT);
    assert_eq!(
        scored,
        Some(CHECKSUM_VALID_FLOOR),
        "a confirmed 2-segment bot token must be kept and floored, not dropped"
    );
    // CHECKSUM_VALID_FLOOR clears the high-precision bar; sanity-pin its value.
    assert_eq!(CHECKSUM_VALID_FLOOR, 0.9);
}

#[test]
fn two_segment_bot_min_secret_15_chars_valid() {
    // Detector 2-segment secret floor is 15 chars; validator must accept it.
    let token = format!(
        "{}-{}-{}",
        concat!("xox", "b"),
        "1234567890",
        "a".repeat(15)
    );
    assert_eq!(token.rsplit('-').next().unwrap().len(), 15);
    assert_eq!(SlackTokenValidator.validate(&token), ChecksumResult::Valid);
}

#[test]
fn two_segment_bot_max_secret_36_chars_valid() {
    // Detector 2-segment secret ceiling is 36; the validator's {15,40} covers it.
    let token = format!(
        "{}-{}-{}",
        concat!("xox", "b"),
        "1234567890",
        "B".repeat(36)
    );
    assert_eq!(token.rsplit('-').next().unwrap().len(), 36);
    assert_eq!(SlackTokenValidator.validate(&token), ChecksumResult::Valid);
}

#[test]
fn two_segment_bot_all_digit_secret_valid() {
    // The 2-segment secret class is [0-9A-Za-z]; an all-digit 15-char secret is
    // a legitimate emission (e.g. xoxb-1234567890-123456789012345) and must not
    // be confused with a missing-secret token.
    let token = format!(
        "{}-{}-{}",
        concat!("xox", "b"),
        "1234567890",
        "1".repeat(15)
    );
    assert_eq!(SlackTokenValidator.validate(&token), ChecksumResult::Valid);
}

// ─────────────── property-style sweep over the legitimate family ────────────

#[test]
fn two_segment_bot_family_all_valid() {
    // Mirror the detector's 2-segment bounds: 10..=13 numeric digits and
    // 15..=36 alnum secret. Every member is a token the detector emits, so the
    // checksum gate must return Valid for all of them.
    for num_len in 10..=13usize {
        for sec_len in 15..=36usize {
            let num = "9".repeat(num_len);
            // Alternate the secret alphabet so we exercise lower/upper/digit.
            let secret: String = (0..sec_len)
                .map(|i| match i % 3 {
                    0 => 'a',
                    1 => 'Z',
                    _ => '7',
                })
                .collect();
            let token = format!("{}-{}-{}", concat!("xox", "b"), num, secret);
            assert_eq!(
                SlackTokenValidator.validate(&token),
                ChecksumResult::Valid,
                "2-segment bot token (num_len={num_len}, sec_len={sec_len}) must be Valid: {token}"
            );
            // And the gate keeps it.
            assert_eq!(
                checksum_adjusted_confidence(0.5, &token),
                Some(CHECKSUM_VALID_FLOOR),
            );
        }
    }
}

#[test]
fn three_segment_bot_token_still_valid() {
    // The canonical 3-segment form must keep working after widening to optional.
    let token = concat!("xox", "b-1234567890-1234567890-abcdefghijklmnopqrstuvwx");
    assert_eq!(SlackTokenValidator.validate(token), ChecksumResult::Valid);
}

// ─────────────────────── negative twins (precision) ────────────────────────

#[test]
fn bot_two_numeric_segments_no_secret_still_invalid() {
    // `xoxb-{10}-{10}` has NO alnum secret at all — the detector's 2-segment
    // pattern also requires a >=15-char secret, so this is correctly Invalid.
    // (Making the middle segment optional must NOT accept this.)
    let token = format!(
        "{}-{}-{}",
        concat!("xox", "b"),
        "0".repeat(10),
        "1".repeat(10)
    );
    assert_eq!(
        SlackTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
    assert_eq!(checksum_adjusted_confidence(0.9, &token), None);
}

#[test]
fn bot_secret_14_chars_still_invalid() {
    // 14-char secret is one short of the 15 floor on both detector patterns.
    let token = format!(
        "{}-{}-{}",
        concat!("xox", "b"),
        "1234567890",
        "a".repeat(14)
    );
    assert_eq!(
        SlackTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn bot_first_segment_9_digits_still_invalid() {
    // 9-digit leading numeric is below the {10,15} floor.
    let token = format!(
        "{}-{}-{}",
        concat!("xox", "b"),
        "0".repeat(9),
        "a".repeat(20)
    );
    assert_eq!(
        SlackTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn bot_first_segment_16_digits_still_invalid() {
    // 16 digits exceeds the {10,15} ceiling — the anchored `$` rejects it.
    let token = format!(
        "{}-{}-{}",
        concat!("xox", "b"),
        "0".repeat(16),
        "a".repeat(20)
    );
    assert_eq!(
        SlackTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn bot_short_garbage_still_invalid() {
    // Classic short junk: must not be confused with the optional-middle form.
    assert_eq!(
        SlackTokenValidator.validate(concat!("xox", "b-bad")),
        ChecksumResult::Invalid
    );
    assert_eq!(
        SlackTokenValidator.validate(concat!("xox", "b-123-456-short")),
        ChecksumResult::Invalid
    );
}

// ───────────────────────── adversarial / evasion ───────────────────────────

#[test]
fn bot_token_with_trailing_garbage_invalid() {
    // Anchored regex: a 2-segment token with trailing junk must fail (so the
    // engine never adjudicates an over-captured span as a confirmed token).
    let token = format!("{} trailing", TWO_SEGMENT_BOT);
    assert_eq!(
        SlackTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn bot_token_secret_with_dash_invalid() {
    // A '-' inside the secret would split it into an extra segment; the secret
    // class is strictly [a-zA-Z0-9], so this is Invalid.
    let token = format!(
        "{}-{}-{}",
        concat!("xox", "b"),
        "1234567890",
        "aaaaaaa-aaaaaaa"
    );
    assert_eq!(
        SlackTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

// ─────────── xoxp lockers: already-correct behavior must be preserved ───────

#[test]
fn user_three_segment_variant_still_valid() {
    // Detector user pattern 2 ("3-segment variant"):
    // xoxp-{10-15}-{10-15}-{24-34 alnum}. Already Valid; lock it.
    let token = concat!("xox", "p-1234567890-1234567890-abcdefghijklmnopqrstuvwx");
    assert_eq!(token.rsplit('-').next().unwrap().len(), 24);
    assert_eq!(SlackTokenValidator.validate(token), ChecksumResult::Valid);
}

#[test]
fn user_four_segment_with_optional_group_still_valid() {
    // Detector user pattern 1: xoxp-{d}-{d}-{d}-{32 hex}. Lock it.
    let token = concat!(
        "xox",
        "p-1234567890-1234567890-1234567890-abcdef1234567890abcdef1234567890"
    );
    assert_eq!(SlackTokenValidator.validate(token), ChecksumResult::Valid);
}

#[test]
fn user_secret_23_chars_still_invalid() {
    // User secret floor is 24 (stricter than the 15 bot floor); 23 is Invalid.
    let token = format!(
        "{}-{}-{}",
        concat!("xox", "p"),
        "1234567890",
        "a".repeat(23)
    );
    assert_eq!(
        SlackTokenValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

// ─────────────────────────── routing sanity ────────────────────────────────

#[test]
fn non_slack_prefix_not_applicable() {
    // Unknown prefix is NotApplicable (not Invalid) — the validator must not
    // claim tokens it does not understand.
    assert_eq!(
        SlackTokenValidator.validate("not-a-slack-token"),
        ChecksumResult::NotApplicable
    );
    assert_eq!(
        SlackTokenValidator.validate(concat!("xox", "r-1234567890-abcdefghijklmnop")),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn validator_id_is_slack_token() {
    assert_eq!(SlackTokenValidator.validator_id(), "slack-token");
}
