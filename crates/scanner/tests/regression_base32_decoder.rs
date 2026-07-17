//! Regression: the ONE real base32 (RFC-4648) decoder keyhog ships.
//!
//! keyhog's decode *pipeline* (base64/hex/url/…/z85/reverse/caesar) has NO
//! base32 stage, that absence is pinned by `regression_base32_decode.rs`. But
//! keyhog DOES contain a genuine RFC-4648 standard base32 decoder in
//! `keyhog-core::aws` (`aws_account_from_key_id`), the routine that handles the
//! only base32-shaped credential keyhog cares about: the 16-char base32 body of
//! an `AKIA…`/`ASIA…` AWS access-key ID, from which the 12-digit owning account
//! number is recovered fully offline (trufflesecurity algorithm). This file
//! pins that decoder's exact decoded values, alphabet handling, fail-closed
//! refusals, and the canary-metadata contract layered on top of it, through the
//! crate's PUBLIC surface (`finding_metadata`, `key_id_canary_status`,
//! `parse_canary_account_ids`, `set_extra_canary_accounts`,
//! `validate_canary_accounts`).
//!
//! All decode vectors were computed independently from the documented algorithm
//! (drop 4-char prefix; base32-decode; first 6 bytes = big-endian u48;
//! `account = (u48 & 0x7fff_ffff_ff80) >> 7`, zero-padded). Nothing here touches
//! an accelerator; the decode is pure arithmetic and host-independent.

#![cfg(feature = "decode")]

use std::collections::HashSet;

use keyhog_core::{
    finding_metadata, key_id_canary_status, parse_canary_account_ids, set_extra_canary_accounts,
    validate_canary_accounts,
};

/// Fetch the decoded `account_id` string from a credential's finding metadata,
/// or `None` when the credential is not a well-formed AWS access-key ID.
fn account_of(credential: &str) -> Option<String> {
    finding_metadata(credential).map(|meta| {
        meta.get("account_id")
            .expect("a decodable AWS key id always attaches account_id metadata")
            .clone()
    })
}

// ---- positive: exact decoded base32 vectors -------------------------------

#[test]
fn known_vector_asia_decodes_exact_account() {
    // ASIAY34FZKBOKMUTVV7A: base32 body Y34FZKBOKM… → account 609629065308.
    assert_eq!(
        account_of("ASIAY34FZKBOKMUTVV7A").as_deref(),
        Some("609629065308"),
        "canonical ASIA vector must base32-decode to 609629065308"
    );
}

#[test]
fn akia_and_asia_same_body_decode_identically() {
    // Both prefixes use the identical 16-char base32 embedding, so an identical
    // body must decode to the identical account regardless of AKIA vs ASIA.
    let akia = account_of("AKIAY34FZKBOKMUTVV7A");
    let asia = account_of("ASIAY34FZKBOKMUTVV7A");
    assert_eq!(akia.as_deref(), Some("609629065308"));
    assert_eq!(asia.as_deref(), Some("609629065308"));
    assert_eq!(akia, asia, "prefix must not change the decoded account");
}

#[test]
fn all_a_body_decodes_to_zero_account() {
    // Base32 'A' == 5-bit value 0, so an all-'A' body is the arithmetic minimum:
    // account 0, rendered zero-padded to 12 digits.
    assert_eq!(
        account_of("AKIAAAAAAAAAAAAAAAAA").as_deref(),
        Some("000000000000"),
        "all-A base32 body is the zero account, zero-padded to 12 digits"
    );
}

#[test]
fn all_sevens_body_yields_thirteen_digit_account_at_boundary() {
    // Base32 '7' == value 31 (top of the 2..=7 range). An all-'7' body drives the
    // masked u48 to its maximum 0xFFFFFFFFFF after the >>7, i.e. 1099511627775
    // which is THIRTEEN decimal digits, not twelve. This pins the true arithmetic
    // upper bound of the decoder and shows the `{:012}` rendering does not (and
    // cannot) truncate an over-max value.
    let account =
        account_of("AKIA7777777777777777").expect("valid base32 body must decode to Some");
    assert_eq!(account, "1099511627775", "all-7 body is the arithmetic max");
    assert_eq!(
        account.len(),
        13,
        "the maximum decodable account overflows the 12-digit contract to 13 digits"
    );
}

#[test]
fn second_alphabet_range_digit_body_decodes_exact() {
    // '2' is the first char of the base32 digit range (value 26). An all-'2' body
    // exercises that range specifically and decodes to a fixed known account.
    assert_eq!(
        account_of("AKIA2222222222222222").as_deref(),
        Some("744830457525"),
        "all-'2' base32 body decodes to 744830457525"
    );
}

#[test]
fn surrounding_whitespace_is_trimmed_before_decode() {
    // The decoder trims before the length/prefix checks, so leading/trailing
    // whitespace around an otherwise-canonical key still decodes.
    assert_eq!(
        account_of("  \tASIAY34FZKBOKMUTVV7A\n").as_deref(),
        Some("609629065308"),
        "whitespace around the key id must be trimmed, then decoded"
    );
}

// ---- negative twins: fail-closed refusals ---------------------------------

#[test]
fn non_base32_digit_in_leading_body_fails_closed() {
    // '0' is OUTSIDE the RFC-4648 base32 alphabet (which omits 0/1/8/9). Placed in
    // the first 10 body chars (the bytes actually decoded), it must fail the whole
    // decode CLOSED → no metadata at all, not a wrong account.
    assert_eq!(
        finding_metadata("AKIA034FZKBOKMUTVV7A"),
        None,
        "a non-base32 digit in the decoded body must fail closed"
    );
}

#[test]
fn lowercase_body_fails_closed() {
    // RFC-4648 base32 is upper-case only; lowercase is out of alphabet. The
    // decoder must NOT case-fold (a lowercased body fails closed).
    assert_eq!(
        finding_metadata("AKIAy34fzkbokmutvv7a"),
        None,
        "lowercase base32 body is out-of-alphabet and must fail closed"
    );
}

#[test]
fn wrong_prefix_fails_closed() {
    // Only AKIA/ASIA carry the embedded account. A well-formed base32 body under
    // any other 4-char prefix must decode to nothing.
    assert_eq!(
        finding_metadata("AAAAY34FZKBOKMUTVV7A"),
        None,
        "non-AKIA/ASIA prefix must fail closed"
    );
    assert_eq!(
        finding_metadata("AKIBY34FZKBOKMUTVV7A"),
        None,
        "near-miss prefix (AKIB) must fail closed"
    );
}

#[test]
fn wrong_length_fails_closed_both_directions() {
    // Canonical length is exactly 20 (4 prefix + 16 body). One char short or one
    // char long both fail closed (the length gate is exact, not a minimum).
    assert_eq!(
        finding_metadata("AKIAY34FZKBOKMUTVV7"),
        None,
        "19-char (one short) must fail closed"
    );
    assert_eq!(
        finding_metadata("AKIAY34FZKBOKMUTVV7AA"),
        None,
        "21-char (one long) must fail closed"
    );
}

#[test]
fn invalid_char_in_trailing_body_is_not_validated() {
    // Only the FIRST 10 base32 chars (the leading 48 account bits) are decoded and
    // validated; the trailing 6 chars are never read. So an out-of-alphabet byte
    // in the last position ('0') does NOT fail the decode, the same account still
    // comes back. This pins the decoder's partial-validation contract precisely so
    // any future full-body validation change is caught.
    assert_eq!(
        account_of("AKIAY34FZKBOKMUTVV70").as_deref(),
        Some("609629065308"),
        "an out-of-alphabet byte beyond the first 10 body chars is not validated"
    );
}

// ---- canary metadata layered on the decode --------------------------------

#[test]
fn non_canary_key_metadata_is_account_id_only() {
    // A decodable, non-canary key attaches EXACTLY one metadata entry: account_id.
    // No is_canary / canary_message keys appear.
    let meta = finding_metadata("AKIA2222222222222222").expect("valid key yields metadata");
    assert_eq!(
        meta.get("account_id").map(String::as_str),
        Some("744830457525")
    );
    assert_eq!(meta.len(), 1, "non-canary metadata is account_id only");
    assert!(
        !meta.contains_key("is_canary"),
        "non-canary key must not carry is_canary"
    );
    assert_eq!(
        key_id_canary_status("AKIA2222222222222222"),
        Ok(false),
        "a non-baseline account is not a canary"
    );
}

#[test]
fn non_key_string_is_not_a_canary_and_has_no_metadata() {
    // A string that is not an AWS key id: no metadata, and the checked canary
    // status is Ok(false) (the None decode path), never an error.
    assert_eq!(finding_metadata("this is not a key"), None);
    assert_eq!(
        key_id_canary_status("this is not a key"),
        Ok(false),
        "an undecodable string is not a canary and must not error"
    );
}

#[test]
fn extra_canary_account_marks_metadata_and_status() {
    // AKIAIOSFODNN7EXAMPLE decodes to account 581039954779 (not in the baseline).
    // Registering it as an extra canary must flip both finding_metadata and the
    // checked status. This account is used ONLY in this test to avoid racing the
    // process-global extra set with the non-canary assertions above.
    assert_eq!(
        account_of("AKIAIOSFODNN7EXAMPLE").as_deref(),
        Some("581039954779"),
        "example key decodes to 581039954779"
    );

    let mut extras = HashSet::new();
    extras.insert("581039954779".to_string());
    set_extra_canary_accounts(extras);

    let meta = finding_metadata("AKIAIOSFODNN7EXAMPLE").expect("valid key yields metadata");
    assert_eq!(
        meta.get("account_id").map(String::as_str),
        Some("581039954779")
    );
    assert_eq!(
        meta.get("is_canary").map(String::as_str),
        Some("true"),
        "an extra-registered canary account must set is_canary=true"
    );
    let message = meta
        .get("canary_message")
        .expect("a canary finding must carry an operator note");
    assert!(
        message.contains("Do NOT verify"),
        "canary note must warn against verification; got {message:?}"
    );
    assert!(
        message.contains("canarytokens.org"),
        "canary note must name the issuer; got {message:?}"
    );
    assert_eq!(
        key_id_canary_status("AKIAIOSFODNN7EXAMPLE"),
        Ok(true),
        "checked status must agree with the metadata"
    );

    // Restore process-global state so no other test observes the extra account.
    set_extra_canary_accounts(HashSet::new());
    assert_eq!(
        key_id_canary_status("AKIAIOSFODNN7EXAMPLE"),
        Ok(false),
        "clearing extras must un-mark the account"
    );
}

// ---- config validation surface --------------------------------------------

#[test]
fn parse_canary_account_ids_accepts_valid_rejects_malformed() {
    // A valid 12-digit account passes and lands in the set.
    let ok = parse_canary_account_ids(["052310077262"]).expect("12-digit id is valid");
    assert_eq!(ok.len(), 1);
    assert!(ok.contains("052310077262"), "the account must be retained");

    // 11 digits (one short) is rejected with a message naming the 12-digit rule.
    let short = parse_canary_account_ids(["05231007726"]).unwrap_err();
    assert!(
        short.contains("12-digit"),
        "short id error must cite the 12-digit rule; got {short:?}"
    );

    // A non-digit char is rejected the same way.
    let nondigit = parse_canary_account_ids(["05231007726X"]).unwrap_err();
    assert!(
        nondigit.contains("12-digit"),
        "non-digit id error must cite the 12-digit rule; got {nondigit:?}"
    );

    // An empty entry is rejected with the empty-specific message.
    let empty = parse_canary_account_ids(["   "]).unwrap_err();
    assert!(
        empty.contains("must not be empty"),
        "blank id must be rejected as empty; got {empty:?}"
    );
}

#[test]
fn baseline_canary_accounts_validate_ok() {
    // The embedded Tier-B canary baseline must parse into a non-corrupt set
    // validate_canary_accounts returns Ok(()) on the shipped data file.
    assert_eq!(
        validate_canary_accounts(),
        Ok(()),
        "shipped aws-canary-accounts.toml must validate"
    );
}

// ---- decode-pipeline linkage ----------------------------------------------

#[cfg(feature = "decode")]
#[test]
fn base32_absent_from_pipeline_but_aws_base32_body_is_handled() {
    // The decode PIPELINE has no base32 stage (that family stays {base64,hex,z85})…
    let names = keyhog_scanner::testing::default_decoder_names_for_test();
    assert!(
        !names.iter().any(|n| *n == "base32"),
        "no `base32` decoder may exist in the default pipeline; got {names:?}"
    );
    // …yet the one base32-shaped credential keyhog handles (an AWS key body) IS
    // decoded, by the dedicated AWS routine, not the generic pipeline. Concrete
    // proof: the same known vector still yields its exact account.
    assert_eq!(
        account_of("ASIAY34FZKBOKMUTVV7A").as_deref(),
        Some("609629065308"),
        "base32-shaped AWS body must be decoded by the AWS path despite no pipeline base32 decoder"
    );
}
