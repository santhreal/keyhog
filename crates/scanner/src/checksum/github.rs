use super::{ChecksumResult, ChecksumValidator};

const BASE62_DIGITS: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Compute the standard CRC32 checksum of `data`.
pub(super) fn crc32(data: &[u8]) -> u32 {
    const TABLE: [u32; 256] = {
        let mut table = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut crc = i as u32;
            let mut j = 0;
            while j < 8 {
                if crc & 1 != 0 {
                    crc = 0xEDB88320 ^ (crc >> 1);
                } else {
                    crc >>= 1;
                }
                j += 1;
            }
            table[i] = crc;
            i += 1;
        }
        table
    };

    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc = TABLE[((crc ^ (byte as u32)) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

/// Encode a `u32` as base62, left-padded with `'0'` to `width` characters.
pub(super) fn base62_encode_u32(mut value: u32, width: usize) -> String {
    if value == 0 {
        return "0".repeat(width);
    }
    let mut rev = Vec::with_capacity(width.max(6));
    while value > 0 {
        rev.push(BASE62_DIGITS[(value % 62) as usize] as char);
        value /= 62;
    }
    while rev.len() < width {
        rev.push('0');
    }
    rev.reverse();
    rev.into_iter().collect()
}

/// Validates GitHub classic personal access tokens.
///
/// Format: `ghp_` + 30-character entropy + 6-character base62 CRC32 checksum.
/// The CRC32 is computed over the 30-character entropy portion only.
pub struct GithubClassicPatValidator;

impl ChecksumValidator for GithubClassicPatValidator {
    fn validator_id(&self) -> &str {
        "github-classic-pat"
    }

    fn validate(&self, credential: &str) -> ChecksumResult {
        let payload = match credential.strip_prefix("ghp_") {
            Some(p) => p,
            None => return ChecksumResult::NotApplicable,
        };
        if payload.len() != 36 {
            return ChecksumResult::NotApplicable;
        }
        if !payload.chars().all(|c| c.is_ascii_alphanumeric()) {
            return ChecksumResult::Invalid;
        }
        let entropy = &payload[..30];
        let checksum_str = &payload[30..];
        let expected = base62_encode_u32(crc32(entropy.as_bytes()), 6);
        if expected == checksum_str {
            ChecksumResult::Valid
        } else {
            ChecksumResult::Invalid
        }
    }
}

/// Validates GitHub fine-grained personal access tokens.
///
/// Format: `github_pat_` + 22 alphanumeric chars + `_` + 59 alphanumeric chars.
pub struct GithubFineGrainedPatValidator;

impl GithubFineGrainedPatValidator {
    fn try_payload(payload: &str) -> ChecksumResult {
        if payload.len() < 7 {
            return ChecksumResult::Invalid;
        }
        let entropy = &payload[..payload.len() - 6];
        let checksum_str = &payload[payload.len() - 6..];
        let expected = base62_encode_u32(crc32(entropy.as_bytes()), 6);
        if expected == checksum_str {
            ChecksumResult::Valid
        } else {
            ChecksumResult::Invalid
        }
    }
}

impl ChecksumValidator for GithubFineGrainedPatValidator {
    fn validator_id(&self) -> &str {
        "github-fine-grained-pat"
    }

    fn validate(&self, credential: &str) -> ChecksumResult {
        let Some(payload) = credential.strip_prefix("github_pat_") else {
            return ChecksumResult::NotApplicable;
        };
        let parts: Vec<&str> = payload.split('_').collect();
        if parts.len() != 2 {
            return ChecksumResult::Invalid;
        }
        let (left, right) = (parts[0], parts[1]);
        if left.len() != 22 || right.len() != 59 {
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
