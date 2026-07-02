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
//!    issuer list is Tier-B data embedded from `data/aws-canary-accounts.toml`.
//!    CLI config may add account IDs through `.keyhog.toml` `[aws]`
//!    `canary_accounts` / `knockoff_accounts`; ambient environment is not part
//!    of this contract. Baseline source:
//!    <https://trufflesecurity.com/blog/canaries>.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

/// The two access-key-ID prefixes whose 12-digit account number is embedded.
/// `AKIA` is a long-term IAM key, `ASIA` a temporary STS session key. Both use
/// the identical embedding, so both decode with the same routine.
const AWS_KEY_ID_PREFIXES: [&str; 2] = ["AKIA", "ASIA"];

/// Length of the 4-char access-key-ID prefix (`AKIA`/`ASIA`) that precedes the
/// base32 body. Single owner for the "skip the prefix" slice offset so the
/// decode routine can never disagree with [`AWS_KEY_ID_PREFIXES`] about where
/// the encoded account bits begin.
const AWS_KEY_ID_PREFIX_LEN: usize = 4;

/// Length of a canonical AWS access-key ID: 4-char prefix + 16 base32 chars.
const AWS_KEY_ID_LEN: usize = AWS_KEY_ID_PREFIX_LEN + 16;

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
pub(crate) fn aws_account_from_key_id(key_id: &str) -> Option<String> {
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
    let body = &key_id.as_bytes()[AWS_KEY_ID_PREFIX_LEN..];
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
/// `data/aws-canary-accounts.toml`.
static BASE_CANARY_ACCOUNTS: std::sync::LazyLock<Result<HashSet<String>, String>> =
    std::sync::LazyLock::new(load_canary_accounts);

static EXTRA_CANARY_ACCOUNTS: OnceLock<std::sync::RwLock<HashSet<String>>> = OnceLock::new();

fn extra_canary_accounts() -> &'static std::sync::RwLock<HashSet<String>> {
    EXTRA_CANARY_ACCOUNTS.get_or_init(|| std::sync::RwLock::new(HashSet::new()))
}

fn load_canary_accounts() -> Result<HashSet<String>, String> {
    let set = parse_canary_accounts(include_str!("../data/aws-canary-accounts.toml")).map_err(
        |error| {
            format!(
                "crates/core/data/aws-canary-accounts.toml is invalid: {error}. \
                 Fix the bundled Tier-B canary list; refusing to run without canary awareness."
            )
        },
    )?;
    if set.is_empty() {
        return Err(
            "crates/core/data/aws-canary-accounts.toml is invalid: no canary accounts. \
             Fix the bundled Tier-B canary list; refusing to run without canary awareness."
                .to_string(),
        );
    }
    Ok(set)
}

/// Validate the compiled Tier-B canary account baseline.
pub fn validate_canary_accounts() -> Result<(), String> {
    base_canary_accounts().map(|_| ())
}

fn base_canary_accounts() -> Result<&'static HashSet<String>, String> {
    match BASE_CANARY_ACCOUNTS.as_ref() {
        Ok(accounts) => Ok(accounts),
        Err(error) => Err(error.clone()),
    }
}

/// `[canary]`/`[knockoff]` TOML shape used by the embedded baseline. Both
/// tables are merged into the same account set — keyhog treats off-brand
/// knockoffs identically to first-party canaries.
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

/// Parse one canary TOML document. Trims each account so whitespace in a
/// hand-edited data file never silently misses.
pub(crate) fn parse_canary_accounts(raw: &str) -> Result<HashSet<String>, String> {
    let parsed: CanaryFile = toml::from_str(raw)
        .map_err(|error| format!("invalid aws-canary-accounts.toml: {error}"))?;
    let mut set = HashSet::new();
    for raw_account in parsed
        .canary
        .accounts
        .into_iter()
        .chain(parsed.knockoff.accounts)
    {
        let account = raw_account.trim();
        if account.is_empty() {
            return Err("canary account entries must not be empty".to_string());
        }
        if account.len() != 12 || !account.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(format!(
                "canary account {account:?} must be a 12-digit AWS account id"
            ));
        }
        set.insert(account.to_string());
    }
    Ok(set)
}

/// Parse and validate raw 12-digit account IDs from `.keyhog.toml` config.
pub fn parse_canary_account_ids<I, S>(accounts: I) -> Result<HashSet<String>, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut set = HashSet::new();
    for raw_account in accounts {
        let account = raw_account.as_ref().trim();
        if account.is_empty() {
            return Err("canary account entries must not be empty".to_string());
        }
        if account.len() != 12 || !account.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(format!(
                "canary account {account:?} must be a 12-digit AWS account id"
            ));
        }
        set.insert(account.to_string());
    }
    Ok(set)
}

/// Replace the process-local extra canary account set supplied by `.keyhog.toml`.
///
/// Passing an empty set clears extras. The embedded baseline is always active.
pub fn set_extra_canary_accounts(accounts: HashSet<String>) {
    let mut guard = match extra_canary_accounts().write() {
        Ok(guard) => guard,
        Err(poisoned) => {
            // LAW10: fail-closed/security: a poisoned process-local
            // canary-extension lock still owns a valid HashSet; recovering
            // preserves explicit canary config and the embedded baseline
            // remains active.
            poisoned.into_inner()
        }
    };
    *guard = accounts;
}

fn account_in_extra_canaries(account_id: &str) -> bool {
    match extra_canary_accounts().read() {
        Ok(accounts) => accounts.contains(account_id),
        Err(poisoned) => {
            // LAW10: fail-closed/security: a poisoned process-local
            // canary-extension lock still owns a valid HashSet; recovering
            // preserves explicit canary config and the embedded baseline
            // remains active.
            poisoned.into_inner().contains(account_id)
        }
    }
}

/// True when `account_id` (a 12-digit AWS account string) belongs to a known
/// canary-token issuer.
#[must_use]
pub(crate) fn account_is_canary(account_id: &str) -> bool {
    base_canary_accounts().is_ok_and(|accounts| accounts.contains(account_id))
        || account_in_extra_canaries(account_id)
}

fn account_is_canary_checked(account_id: &str) -> Result<bool, String> {
    Ok(base_canary_accounts()?.contains(account_id) || account_in_extra_canaries(account_id))
}

/// Checked canary classifier used by live-verification paths.
///
/// This surfaces a corrupt embedded baseline as an error so callers can fail
/// closed before any network verification.
pub fn key_id_canary_status(key_id: &str) -> Result<bool, String> {
    match aws_account_from_key_id(key_id) {
        Some(account_id) => account_is_canary_checked(&account_id),
        None => Ok(false),
    }
}

/// Operator-facing note attached to a canary finding so the report explains why
/// verification was skipped. Mirrors trufflehog's responder message.
pub(crate) const CANARY_MESSAGE: &str =
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
