//! AWS access-key detector internals — exact classification, the
//! access-key/session-token/secret companion distinction, offline account
//! decode, and canary-token flagging, all pinned to CONCRETE expected values.
//!
//! Two production surfaces are exercised together, both through the crate's
//! PUBLIC api (this is an external integration crate — it sees only the public
//! surface + the `keyhog_core::testing` facade, never `#[cfg(test)]` helpers):
//!
//!   1. The compiled scanner (`support::contracts::scanner`) — an `AKIA…`/
//!      `ASIA…` id must classify under detector `aws-access-key`, service
//!      `aws`, severity `Critical`, name `AWS Access Key`, capturing the whole
//!      20-char id as the credential; a nearby `AWS_SESSION_TOKEN` and
//!      `AWS_SECRET_ACCESS_KEY` land in the companion map under the EXACT and
//!      DISTINCT keys `session_token` / `secret_key`; a lowercase look-alike,
//!      an over-length run, and the canonical `…EXAMPLE` doc placeholder are
//!      each rejected.
//!
//!   2. The offline metadata path (`keyhog_scanner::aws::finding_metadata`,
//!      `keyhog_core::key_id_canary_status`, and the `keyhog_core::testing`
//!      decode facade) — every well-formed id yields its 12-digit account with
//!      no network; a decoded account that belongs to a baseline
//!      canarytokens.org / knockoff issuer flags `is_canary=true` with the
//!      exact operator note; a non-base32 body char (e.g. the digit `0`, which
//!      the regex's `[0-9A-Z]` class allows but base32 forbids) fails the
//!      decode CLOSED to `None`; and `.keyhog.toml` `canary_accounts` config
//!      extends the classification.
//!
//! Test vectors were generated offline by inverting the documented decode
//! (`account = (u48 & 0x7fff_ffff_ff80) >> 7`, first 10 base32 body chars) so
//! every account assertion is a literal, not a runtime-derived value:
//!   AKIA `AKIABZPUZDIKAUZZ7Q4X` → account 123456789012 (not a canary)
//!   ASIA `ASIAOL5GI6PFCEMJV8KT` → account 987654321098 (not a canary)
//!   AKIA `AKIAAYLPMN5HAMQWERTY` → account 052310077262 (first-party canary)
//!   ASIA `ASIAAU4OL7HGRELKJHGF` → account 044858866125 (knockoff canary)
//!   AKIA `AKIABTXV5AIPQEPLMOKN` → account 111111111199 (config-extended)
//! Baseline canary accounts: `crates/core/data/aws-canary-accounts.toml`.

mod support;

use std::collections::HashSet;
use std::sync::OnceLock;

use keyhog_core::testing::{CoreTestApi, TestApi};
use keyhog_core::{Chunk, RawMatch, Severity};
use keyhog_scanner::aws::finding_metadata;
use keyhog_scanner::CompiledScanner;
use support::contracts::{make_chunk, scanner};

// ── literal test vectors (see module docs; all offline-verified) ─────────────
const AKIA_ACCT_123456789012: &str = "AKIABZPUZDIKAUZZ7Q4X";
const ASIA_ACCT_987654321098: &str = "ASIAOL5GI6PFCEMJV8KT";
const AKIA_CANARY_FIRSTPARTY: &str = "AKIAAYLPMN5HAMQWERTY"; // → 052310077262
const ASIA_CANARY_KNOCKOFF: &str = "ASIAAU4OL7HGRELKJHGF"; // → 044858866125
const AKIA_EXTRA_CANARY: &str = "AKIABTXV5AIPQEPLMOKN"; // → 111111111199

// A 40-char base62 secret body and a 90-char session token (both match the
// companion regex character classes; the session token is >= the 80-char floor).
const AWS_SECRET: &str = "nvFR5lDXjH7z3z7HjXDl5RFvnhdbbdhnvFR5lDXj";
const AWS_SESSION_TOKEN: &str =
    "FwoGZXIvYXdzEMoLKzP9qR2sT5uV8wX1yA4bC7dE0fG3hJ6kM9nQ2rT5uW8xZ1bD4fH7jL0mP3qS6vY9wZ2cF5hK8n";

// The exact operator note attached to a canary finding (single source of truth
// in `keyhog_core::aws::CANARY_MESSAGE`; asserted literally AND against the
// testing facade so a silent edit of either side fails the test).
const CANARY_MESSAGE: &str =
    "AWS canary token (canarytokens.org / Thinkst-style). Do NOT verify: a \
     verification request alerts whoever planted it. See \
     https://trufflesecurity.com/canaries";

/// One compiled scanner for the whole file — `scanner()` recompiles every
/// on-disk detector per call, so the `OnceLock` keeps the suite fast. The
/// scanner is `Send + Sync`; the fragment cache is cleared before each scan.
fn shared() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(scanner)
}

fn matches_for(text: &str) -> Vec<RawMatch> {
    let s = shared();
    s.clear_fragment_cache();
    let chunk: Chunk = make_chunk(text, "filesystem", "aws.conf");
    s.scan(&chunk)
}

fn by_detector(text: &str, detector_id: &str) -> Vec<RawMatch> {
    matches_for(text)
        .into_iter()
        .filter(|m| m.detector_id.as_ref() == detector_id)
        .collect()
}

/// The single `detector_id` match, asserting exactly one exists. A count other
/// than 1 names the whole match set so a miss/duplicate is concrete.
fn only(text: &str, detector_id: &str) -> RawMatch {
    let mut hits = by_detector(text, detector_id);
    assert_eq!(
        hits.len(),
        1,
        "expected exactly one `{detector_id}` match, got {}: {:?}",
        hits.len(),
        hits.iter()
            .map(|m| (m.detector_id.as_ref(), m.location.line))
            .collect::<Vec<_>>()
    );
    hits.pop().unwrap()
}

// ── 1. classification: service + kind (detector) + severity + name ───────────

#[test]
fn akia_classifies_as_aws_access_key_with_exact_service_kind_severity_name() {
    // Key sits on physical line 3 (comment, section header, then the key line).
    let text =
        format!("# ~/.aws/credentials\n[default]\naws_access_key_id = {AKIA_ACCT_123456789012}\n");
    let m = only(&text, "aws-access-key");
    assert_eq!(
        m.detector_id.as_ref(),
        "aws-access-key",
        "kind == detector id"
    );
    assert_eq!(m.service.as_ref(), "aws", "service namespace");
    assert_eq!(m.detector_name.as_ref(), "AWS Access Key", "human name");
    assert_eq!(m.severity, Severity::Critical, "AWS keys are critical");
    assert_eq!(
        m.credential.as_ref(),
        AKIA_ACCT_123456789012,
        "whole 20-char AKIA id is the credential"
    );
    assert_eq!(
        m.location.line,
        Some(3),
        "key is on the third physical line"
    );
}

#[test]
fn asia_session_id_shares_the_aws_access_key_detector() {
    // An ASIA temporary/STS access-key id uses the SAME embedding and the SAME
    // detector as a long-term AKIA id — no separate "aws-session-key" kind.
    let text = format!("[profile ci]\naws_access_key_id={ASIA_ACCT_987654321098}\n");
    let m = only(&text, "aws-access-key");
    assert_eq!(m.detector_id.as_ref(), "aws-access-key");
    assert_eq!(m.service.as_ref(), "aws");
    assert_eq!(m.credential.as_ref(), ASIA_ACCT_987654321098);
    assert_eq!(m.location.line, Some(2), "key is on the second line");
}

// ── 2. companion distinction: session-token vs secret-key are separate keys ──

#[test]
fn asia_with_secret_and_session_token_captures_both_companions_distinctly() {
    // Real STS creds block: access-key id + secret + session token within the
    // 5-line companion window. The 40-char secret must land under `secret_key`
    // and the 90-char token under `session_token` — never swapped or merged.
    let text = format!(
        "[default]\naws_access_key_id = {ASIA_ACCT_987654321098}\n\
         aws_secret_access_key = {AWS_SECRET}\naws_session_token = {AWS_SESSION_TOKEN}\n"
    );
    let m = only(&text, "aws-access-key");
    assert_eq!(m.credential.as_ref(), ASIA_ACCT_987654321098);
    assert_eq!(
        m.companions.get("secret_key").map(String::as_str),
        Some(AWS_SECRET),
        "40-char body captured under the `secret_key` companion"
    );
    assert_eq!(
        m.companions.get("session_token").map(String::as_str),
        Some(AWS_SESSION_TOKEN),
        "90-char token captured under the `session_token` companion"
    );
}

#[test]
fn asia_mixed_case_fields_capture_complete_temporary_credentials() {
    let text = format!(
        "Aws_Access_Key_Id = {ASIA_ACCT_987654321098}\n\
         Aws_Secret_Access_Key = {AWS_SECRET}\nAws_Session_Token = {AWS_SESSION_TOKEN}\n"
    );
    let m = only(&text, "aws-access-key");
    assert_eq!(m.credential.as_ref(), ASIA_ACCT_987654321098);
    assert_eq!(
        m.companions.get("secret_key").map(String::as_str),
        Some(AWS_SECRET),
        "mixed-case secret field preserves the exact secret"
    );
    assert_eq!(
        m.companions.get("session_token").map(String::as_str),
        Some(AWS_SESSION_TOKEN),
        "mixed-case session field preserves the token required by ASIA verification"
    );
}

#[test]
fn akia_with_only_session_token_captures_session_token_not_secret() {
    // No `AWS_SECRET…` anchor present: the `secret_key` companion must be
    // ABSENT (not empty-string, not the token) while `session_token` is exact.
    // This is the precise access-key/session-token/secret distinction.
    let text = format!(
        "aws_access_key_id = {AKIA_ACCT_123456789012}\nAWS_SESSION_TOKEN = {AWS_SESSION_TOKEN}\n"
    );
    let m = only(&text, "aws-access-key");
    assert_eq!(
        m.companions.get("session_token").map(String::as_str),
        Some(AWS_SESSION_TOKEN)
    );
    assert_eq!(
        m.companions.get("secret_key"),
        None,
        "no secret anchor ⇒ no `secret_key` companion"
    );
}

// ── 3. negative twins / boundaries: look-alikes rejected ─────────────────────

#[test]
fn lowercase_akia_lookalike_is_not_classified_as_aws_access_key() {
    // `(?-i)` forces case-sensitivity: the lowercased doc/test look-alike must
    // NOT attribute to aws-access-key.
    let lower = AKIA_ACCT_123456789012.to_ascii_lowercase();
    let text = format!("key = {lower}\n");
    assert_eq!(
        by_detector(&text, "aws-access-key").len(),
        0,
        "lowercase AKIA look-alike is not an access key id"
    );
}

#[test]
fn overlong_21_char_akia_run_is_rejected_by_right_boundary() {
    // An AWS access-key id is EXACTLY 20 chars; the trailing `\b` fails closed
    // on a 21-char contiguous upper-alnum run.
    let overlong = format!("{AKIA_ACCT_123456789012}X"); // 21 chars
    let text = format!("token = {overlong}\n");
    assert_eq!(
        by_detector(&text, "aws-access-key").len(),
        0,
        "a 21-char AKIA run is not a valid access key id"
    );
}

#[test]
fn documentation_example_akia_is_suppressed() {
    // The canonical AWS docs id ends in `EXAMPLE`; doc-marker suppression drops
    // it even though it is shape-valid.
    let text = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n";
    assert_eq!(
        by_detector(text, "aws-access-key").len(),
        0,
        "AKIAIOSFODNN7EXAMPLE is a documentation placeholder, not a leak"
    );
}

// ── 4. offline account decode (finding metadata) ─────────────────────────────

#[test]
fn finding_metadata_decodes_akia_account_with_no_canary_flag() {
    let meta = finding_metadata(AKIA_ACCT_123456789012)
        .expect("well-formed AKIA id yields offline metadata");
    assert_eq!(
        meta.get("account_id").map(String::as_str),
        Some("123456789012"),
        "12-digit account decoded fully offline"
    );
    assert_eq!(
        meta.get("is_canary"),
        None,
        "a normal account is not flagged as a canary"
    );
    assert_eq!(meta.get("canary_message"), None);
}

#[test]
fn finding_metadata_decodes_asia_account_zero_padded() {
    let meta = finding_metadata(ASIA_ACCT_987654321098).expect("well-formed ASIA id");
    assert_eq!(
        meta.get("account_id").map(String::as_str),
        Some("987654321098"),
        "ASIA temporary keys decode with the identical embedding"
    );
    assert_eq!(meta.get("is_canary"), None);
}

#[test]
fn finding_metadata_rejects_lowercase_lookalike_as_undecodable() {
    // Case-sensitive prefix check: a lowercase id is not an AWS key id, so the
    // whole offline decode returns None (no fabricated account).
    let lower = AKIA_ACCT_123456789012.to_ascii_lowercase();
    assert!(
        finding_metadata(&lower).is_none(),
        "lowercase look-alike has no decodable AWS account"
    );
    // And the internal decode facade agrees exactly.
    assert_eq!(TestApi.aws_account_from_key_id(&lower), None);
}

#[test]
fn decode_fails_closed_on_non_base32_digit_in_body() {
    // `0` is inside the detector's `[0-9A-Z]` char class but OUTSIDE the RFC-4648
    // base32 alphabet (which omits 0/1/8/9). The decode must fail CLOSED to
    // None rather than silently mis-decoding an account.
    let bad = "AKIA0BCDEFGHIJKLMNOP"; // valid length + prefix, `0` in body
    assert_eq!(
        TestApi.aws_account_from_key_id(bad),
        None,
        "a non-base32 body byte fails the decode closed"
    );
    assert!(
        finding_metadata(bad).is_none(),
        "no offline metadata for an undecodable body"
    );
}

// ── 5. canary-token classification ───────────────────────────────────────────

#[test]
fn first_party_canary_key_flags_is_canary_with_exact_message() {
    let meta = finding_metadata(AKIA_CANARY_FIRSTPARTY).expect("decodable canary key");
    assert_eq!(
        meta.get("account_id").map(String::as_str),
        Some("052310077262"),
        "decoded account is a baseline canarytokens.org issuer"
    );
    assert_eq!(
        meta.get("is_canary").map(String::as_str),
        Some("true"),
        "known canary issuer ⇒ is_canary=true"
    );
    assert_eq!(
        meta.get("canary_message").map(String::as_str),
        Some(CANARY_MESSAGE),
        "the exact do-NOT-verify operator note is attached"
    );
    // The literal above must equal the single-source-of-truth const.
    assert_eq!(TestApi.aws_canary_message(), CANARY_MESSAGE);
}

#[test]
fn knockoff_canary_asia_key_is_flagged_identically() {
    // Off-brand knockoff issuers are treated identically to first-party ones.
    let meta = finding_metadata(ASIA_CANARY_KNOCKOFF).expect("decodable knockoff key");
    assert_eq!(
        meta.get("account_id").map(String::as_str),
        Some("044858866125")
    );
    assert_eq!(meta.get("is_canary").map(String::as_str), Some("true"));
    assert_eq!(
        TestApi.aws_account_is_canary("044858866125"),
        true,
        "knockoff account classifies as canary via the decode facade"
    );
}

#[test]
fn key_id_canary_status_is_exact_for_members_and_non_members() {
    // The checked classifier surfaces a clean Ok(bool) per key.
    assert_eq!(
        keyhog_core::key_id_canary_status(AKIA_CANARY_FIRSTPARTY),
        Ok(true),
        "baseline canary key ⇒ Ok(true)"
    );
    assert_eq!(
        keyhog_core::key_id_canary_status(AKIA_ACCT_123456789012),
        Ok(false),
        "a normal decodable key ⇒ Ok(false)"
    );
    assert_eq!(
        keyhog_core::key_id_canary_status("not-a-key"),
        Ok(false),
        "an undecodable id is not a canary (Ok(false), never Err)"
    );
}

// ── 6. Tier-B / .keyhog.toml canary-account config ───────────────────────────

#[test]
fn parse_canary_account_ids_validates_12_digit_shape() {
    // Whitespace is trimmed; the value must be exactly 12 ASCII digits.
    let ok = keyhog_core::parse_canary_account_ids([" 052310077262 "])
        .expect("a trimmed 12-digit account parses");
    assert!(
        ok.contains("052310077262"),
        "trimmed account is stored canonically"
    );
    assert_eq!(ok.len(), 1);

    let short = keyhog_core::parse_canary_account_ids(["12345678901"]).unwrap_err();
    assert!(
        short.contains("must be a 12-digit AWS account id"),
        "an 11-digit account is rejected: {short}"
    );

    let nondigit = keyhog_core::parse_canary_account_ids(["12345678901z"]).unwrap_err();
    assert!(
        nondigit.contains("must be a 12-digit AWS account id"),
        "a 12-char non-digit account is rejected: {nondigit}"
    );

    // The compiled Tier-B baseline itself validates cleanly.
    assert_eq!(keyhog_core::validate_canary_accounts(), Ok(()));
}

#[test]
fn extra_canary_account_config_extends_classification() {
    // A `.keyhog.toml` `[aws] canary_accounts` entry flips a previously-clean
    // account to canary; account 111111111199 is used by no other test, so the
    // process-global extension can't race a concurrent assertion.
    let acct = "111111111199";

    // Before: not a canary.
    let before = finding_metadata(AKIA_EXTRA_CANARY).expect("decodable key");
    assert_eq!(before.get("account_id").map(String::as_str), Some(acct));
    assert_eq!(
        before.get("is_canary"),
        None,
        "clean before config extension"
    );

    keyhog_core::set_extra_canary_accounts(HashSet::from([acct.to_string()]));

    // After: flagged as canary with the operator note.
    let after = finding_metadata(AKIA_EXTRA_CANARY).expect("decodable key");
    assert_eq!(
        after.get("is_canary").map(String::as_str),
        Some("true"),
        "config-added account now classifies as canary"
    );
    assert_eq!(
        after.get("canary_message").map(String::as_str),
        Some(CANARY_MESSAGE)
    );

    // Restore: clear the process-local extension so nothing leaks.
    keyhog_core::set_extra_canary_accounts(HashSet::new());
    let restored = finding_metadata(AKIA_EXTRA_CANARY).expect("decodable key");
    assert_eq!(
        restored.get("is_canary"),
        None,
        "clearing the extension reverts classification"
    );
}
