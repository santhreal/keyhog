use super::{base62_encode_u32, crc32, ChecksumResult, ChecksumValidator};

/// GitHub/npm CRC32 token checksums are a 6-character base62 encoding of the
/// body's CRC32. Single owner so the classic and fine-grained validators agree
/// on the checksum width.
const CHECKSUM_LEN: usize = 6;
/// GitHub classic PAT body: a fixed entropy run followed by the checksum.
const GITHUB_CLASSIC_ENTROPY_LEN: usize = 30;
const GITHUB_CLASSIC_BODY_LEN: usize = GITHUB_CLASSIC_ENTROPY_LEN + CHECKSUM_LEN;
/// GitHub fine-grained PAT payload segments: `{LEFT}_{RIGHT}`.
const GITHUB_FINE_GRAINED_LEFT_LEN: usize = 22;
const GITHUB_FINE_GRAINED_RIGHT_LEN: usize = 59;

/// Validates GitHub classic personal access tokens AND the OAuth-family tokens
/// that share the identical body (`gho_`/`ghu_`/`ghs_`/`ghr_`).
///
/// Format: `{ghp_|gho_|ghu_|ghs_|ghr_}` + 30-character entropy + 6-character
/// base62 CRC32 checksum. The CRC32 is computed over the 30-character entropy
/// portion ONLY, so it is prefix-independent, the same validator serves all
/// five families (their prefixes are single-sourced in `prefixes.rs`).
pub(crate) struct GithubClassicPatValidator;

impl ChecksumValidator for GithubClassicPatValidator {
    fn validate(&self, credential: &str) -> ChecksumResult {
        // ghp_ (classic PAT) and the OAuth-family siblings (gho_/ghu_/ghs_/ghr_)
        // share the identical `_`+30-entropy+6-CRC32-base62 body, the CRC is over
        // the 30-char entropy only, so it is prefix-independent. Strip whichever
        // of the five recognised prefixes matches.
        let payload = std::iter::once(super::prefixes::GITHUB_CLASSIC_PAT)
            .chain(super::prefixes::GITHUB_OAUTH_FAMILY_PREFIXES)
            .find_map(|p| credential.strip_prefix(p));
        let payload = match payload {
            Some(p) => p,
            None => return ChecksumResult::NotApplicable,
        };
        if payload.len() > GITHUB_CLASSIC_BODY_LEN {
            return ChecksumResult::Invalid;
        }
        if payload.len() != GITHUB_CLASSIC_BODY_LEN {
            return ChecksumResult::NotApplicable;
        }
        if !payload.chars().all(|c| c.is_ascii_alphanumeric()) {
            return ChecksumResult::Invalid;
        }
        let entropy = &payload[..GITHUB_CLASSIC_ENTROPY_LEN];
        let checksum_str = &payload[GITHUB_CLASSIC_ENTROPY_LEN..];
        let expected = base62_encode_u32(crc32(entropy.as_bytes()), CHECKSUM_LEN);
        if expected == checksum_str {
            ChecksumResult::Valid
        } else {
            // A well-formed `ghp_` + 36-alnum token whose trailing 6-char
            // base62 CRC32 does not match its 30-char body is fabricated or
            // corrupted - exactly what the checksum exists to reject. The
            // algorithm is proven correct by the `github_classic_valid` /
            // `_all_as_valid` oracles, so a mismatch is `Invalid` (capped to
            // low confidence), not `NotApplicable`. Mirrors the fine-grained
            // validator, which already rejects on CRC mismatch.
            ChecksumResult::Invalid
        }
    }
}

/// Validates GitHub fine-grained personal access tokens.
///
/// Format: `github_pat_` + 22 alphanumeric chars + `_` + 59 alphanumeric chars.
pub(crate) struct GithubFineGrainedPatValidator;

impl GithubFineGrainedPatValidator {
    fn try_payload(payload: &str) -> ChecksumResult {
        if payload.len() < CHECKSUM_LEN + 1 {
            return ChecksumResult::Invalid;
        }
        let entropy = &payload[..payload.len() - CHECKSUM_LEN];
        let checksum_str = &payload[payload.len() - CHECKSUM_LEN..];
        let expected = base62_encode_u32(crc32(entropy.as_bytes()), CHECKSUM_LEN);
        if expected == checksum_str {
            ChecksumResult::Valid
        } else {
            ChecksumResult::Invalid
        }
    }
}

fn split_fine_grained_payload(payload: &str) -> Option<(&str, &str)> {
    let (left, right) = payload.split_once('_')?;
    if right.contains('_') {
        return None;
    }
    Some((left, right))
}

impl ChecksumValidator for GithubFineGrainedPatValidator {
    fn validate(&self, credential: &str) -> ChecksumResult {
        let Some(payload) = credential.strip_prefix(super::prefixes::GITHUB_PAT_FINE_GRAINED)
        else {
            return ChecksumResult::NotApplicable;
        };
        let Some((left, right)) = split_fine_grained_payload(payload) else {
            return ChecksumResult::Invalid;
        };
        if left.len() != GITHUB_FINE_GRAINED_LEFT_LEN
            || right.len() != GITHUB_FINE_GRAINED_RIGHT_LEN
        {
            return ChecksumResult::Invalid;
        }
        if !left.chars().all(|c| c.is_ascii_alphanumeric())
            || !right.chars().all(|c| c.is_ascii_alphanumeric())
        {
            return ChecksumResult::Invalid;
        }

        if Self::try_payload(payload) == ChecksumResult::Valid {
            return ChecksumResult::Valid;
        }
        if Self::try_payload(right) == ChecksumResult::Valid {
            return ChecksumResult::Valid;
        }
        ChecksumResult::Invalid
    }
}
