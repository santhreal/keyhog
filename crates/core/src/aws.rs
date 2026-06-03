//! Offline AWS account-ID recovery and canary-token classification.
//!
//! This is the **single source of truth** for two credential-string-only facts
//! about an AWS access-key ID, shared by every keyhog crate (scanner attaches
//! them as finding metadata with no verify; verifier consults the canary check
//! to refuse tripping a canary on `--verify`). It lives in `keyhog-core` — the
//! one crate both `keyhog-scanner` and `keyhog-verifier` depend on — so there is
//! exactly one decode and one canary list, never a fork.
//!
//! 1. **Account decode.** Every modern AWS access-key ID (`AKIA…` long-term,
//!    `ASIA…` temporary STS) has the 12-digit account number mathematically
//!    embedded in it, recoverable with a pure base32-decode + bit-shift — NO
//!    network call, NO STS `GetCallerIdentity`, and it works on LIVE *and*
//!    revoked keys. Algorithm matches the trufflesecurity write-up
//!    <https://trufflesecurity.com/blog/research-uncovers-aws-account-numbers-hidden-in-access-keys>:
//!    drop the 4-char prefix; base32-decode the body; the first 6 decoded bytes
//!    are a big-endian u48; `account = (u48 & 0x7fff_ffff_ff80) >> 7`, rendered
//!    as a 12-digit zero-padded decimal string.
//!
//! 2. **Canary classification.** An access key whose decoded account belongs to
//!    a known canary issuer (canarytokens.org / Thinkst and off-brand clones) is
//!    a tripwire: any live verification alerts whoever planted it. The baseline
//!    issuer list is Tier-B data embedded from `data/aws-canary-accounts.toml`
//!    and unioned at first use with a runtime-extension file pointed to by
//!    `KEYHOG_AWS_CANARY_ACCOUNTS`. Baseline source:
//!    <https://trufflesecurity.com/blog/canaries>.

use std::collections::{HashMap, HashSet};

/// The two access-key-ID prefixes whose 12-digit account number is embedded.
/// `AKIA` is a long-term IAM key, `ASIA` a temporary STS session key. Both use
/// the identical embedding, so both decode with the same routine.
const AWS_KEY_ID_PREFIXES: [&str; 2] = ["AKIA", "ASIA"];

/// Length of a canonical AWS access-key ID: 4-char prefix + 16 base32 chars.
const AWS_KEY_ID_LEN: usize = 20;

/// The 48-bit mask + 7-bit right shift that extracts the account number from
/// the leading 6 decoded bytes. Documented by trufflesecurity; the low 7 bits
/// are a non-account discriminator, and bit 47 is always 0 for the account.
const ACCOUNT_MASK: u64 = 0x7fff_ffff_ff80;
const ACCOUNT_SHIFT: u64 = 7;

/// Decode an RFC-4648 standard base32 character (`A`-`Z`, `2`-`7`) to its 5-bit
/// value. Returns `None` for any out-of-alphabet byte (lowercase, padding,
/// digits 0/1/8/9), which makes the whole decode fail closed on a malformed id.
#[inline]
fn base32_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'2'..=b'7' => Some(c - b'2' + 26),
        _ => None,
    }
}

/// Recover the 12-digit AWS account ID embedded in an access-key ID, fully
/// offline. Returns `None` when `key_id` is not a well-formed `AKIA…`/`ASIA…`
/// access-key ID (wrong length, wrong prefix, or a non-base32 body), so a
/// caller can blindly try every credential and only act on `Some`.
///
/// The returned string is always exactly 12 ASCII digits, zero-padded — AWS
/// account numbers are 12-digit identifiers and the leading-zero form (e.g.
/// `052310077262`) is the canonical rendering, matching the STS `Account`
/// field and trufflehog's output.
#[must_use]
pub fn aws_account_from_key_id(key_id: &str) -> Option<String> {
    let key_id = key_id.trim();
    if key_id.len() != AWS_KEY_ID_LEN {
        return None;
    }
    if !AWS_KEY_ID_PREFIXES
        .iter()
        .any(|p| key_id.as_bytes().starts_with(p.as_bytes()))
    {
        return None;
    }

    // The 16 base32 chars after the prefix encode 80 bits; we only need the
    // leading 48 bits (first 6 bytes), which come from the first 10 base32
    // chars (10 * 5 = 50 bits). Accumulate those 50 bits, then keep the top 48.
    let body = &key_id.as_bytes()[4..];
    let mut acc: u64 = 0;
    for &c in &body[..10] {
        let v = base32_value(c)?;
        acc = (acc << 5) | u64::from(v);
    }
    // `acc` now holds 50 bits (the first 10 chars). The leading 48 bits are the
    // u48 we want, so drop the low 2 bits.
    let u48 = acc >> 2;
    let account = (u48 & ACCOUNT_MASK) >> ACCOUNT_SHIFT;
    Some(format!("{account:012}"))
}

/// The Tier-B baseline canary account list, compiled into the binary from
/// `data/aws-canary-accounts.toml`, unioned at first use with any runtime
/// extension file pointed to by `KEYHOG_AWS_CANARY_ACCOUNTS`.
///
/// Soft-fails to an empty set so a corrupted data file degrades canary
/// awareness rather than crashing.
static CANARY_ACCOUNTS: std::sync::LazyLock<HashSet<String>> = std::sync::LazyLock::new(|| {
    let mut set = HashSet::new();
    merge_canary_accounts(&mut set, include_str!("../data/aws-canary-accounts.toml"));
    if let Ok(path) = std::env::var("KEYHOG_AWS_CANARY_ACCOUNTS") {
        match std::fs::read_to_string(&path) {
            Ok(raw) => merge_canary_accounts(&mut set, &raw),
            Err(e) => tracing::warn!(
                path = %path,
                error = %e,
                "KEYHOG_AWS_CANARY_ACCOUNTS points at an unreadable file; \
                 using the compiled-in canary baseline only"
            ),
        }
    }
    set
});

/// `[canary]`/`[knockoff]` TOML shape shared by the baseline and any runtime
/// extension file. Both tables are merged into the same account set — keyhog
/// treats off-brand knockoffs identically to first-party canaries.
#[derive(serde::Deserialize, Default)]
struct CanaryFile {
    #[serde(default)]
    canary: CanaryTable,
    #[serde(default)]
    knockoff: CanaryTable,
}

#[derive(serde::Deserialize, Default)]
struct CanaryTable {
    #[serde(default)]
    accounts: Vec<String>,
}

/// Parse one canary TOML document and union its accounts into `set`. Trims each
/// account so whitespace in a hand-edited extension file never silently misses.
fn merge_canary_accounts(set: &mut HashSet<String>, raw: &str) {
    match toml::from_str::<CanaryFile>(raw) {
        Ok(parsed) => {
            for acct in parsed
                .canary
                .accounts
                .into_iter()
                .chain(parsed.knockoff.accounts)
            {
                let acct = acct.trim();
                if !acct.is_empty() {
                    set.insert(acct.to_string());
                }
            }
        }
        Err(e) => tracing::warn!(
            error = %e,
            "aws-canary-accounts.toml failed to parse; canary awareness disabled this run"
        ),
    }
}

/// True when `account_id` (a 12-digit AWS account string) belongs to a known
/// canary-token issuer.
#[must_use]
pub fn account_is_canary(account_id: &str) -> bool {
    CANARY_ACCOUNTS.contains(account_id)
}

/// True when `key_id` is a decodable AWS access-key ID whose offline-decoded
/// account belongs to a known canary issuer. The verifier uses this to refuse
/// sending a live probe (which would trip the canary) without re-implementing
/// the decode.
#[must_use]
pub fn key_id_is_canary(key_id: &str) -> bool {
    aws_account_from_key_id(key_id).is_some_and(|acct| account_is_canary(&acct))
}

/// Operator-facing note attached to a canary finding so the report explains why
/// verification was skipped. Mirrors trufflehog's responder message.
pub const CANARY_MESSAGE: &str =
    "AWS canary token (canarytokens.org / Thinkst-style). Do NOT verify: a \
     verification request alerts whoever planted it. See \
     https://trufflesecurity.com/canaries";

/// Build the offline metadata for an AWS-access-key finding: always
/// `{ "account_id": "<12 digits>" }` for a decodable `AKIA…`/`ASIA…` key, plus
/// `{ "is_canary": "true", "canary_message": <note> }` when the decoded account
/// belongs to a known canary issuer. `None` when `credential` is not a
/// well-formed AWS access-key ID.
///
/// The `HashMap<String, String>` shape lets a [`crate::VerifiedFinding`]'s
/// `metadata` absorb it directly, with no verify and no network.
#[must_use]
pub fn finding_metadata(credential: &str) -> Option<HashMap<String, String>> {
    let account_id = aws_account_from_key_id(credential)?;
    let is_canary = account_is_canary(&account_id);
    let mut meta = HashMap::new();
    meta.insert("account_id".to_string(), account_id);
    if is_canary {
        meta.insert("is_canary".to_string(), "true".to_string());
        meta.insert("canary_message".to_string(), CANARY_MESSAGE.to_string());
    }
    Some(meta)
}
