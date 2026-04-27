use super::github::{base62_encode_u32, crc32};
use super::{ChecksumResult, ChecksumValidator};

/// Validates modern npm access tokens.
///
/// New-format npm tokens follow the same design as GitHub tokens:
/// `npm_` + 30-character entropy + 6-character base62 CRC32 checksum.
pub struct NpmTokenValidator;

impl ChecksumValidator for NpmTokenValidator {
    fn validator_id(&self) -> &str {
        "npm-access-token"
    }

    fn validate(&self, credential: &str) -> ChecksumResult {
        let payload = match credential.strip_prefix("npm_") {
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

/// Validates PyPI API tokens.
///
/// PyPI tokens are `pypi-` followed by a base64-encoded macaroon. We cannot
/// verify the macaroon's HMAC signature without PyPI's secret key, but we can
/// confirm that the payload is well-formed base64 and decodes to a non-trivial
/// binary blob.
pub struct PypiTokenValidator;

impl ChecksumValidator for PypiTokenValidator {
    fn validator_id(&self) -> &str {
        "pypi-api-token"
    }

    fn validate(&self, credential: &str) -> ChecksumResult {
        let payload = match credential.strip_prefix("pypi-") {
            Some(p) => p,
            None => return ChecksumResult::NotApplicable,
        };
        if payload.len() < 20 {
            return ChecksumResult::Invalid;
        }
        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload)
                .or_else(|_| {
                    base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD_NO_PAD,
                        payload,
                    )
                })
                .or_else(|_| {
                    base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE, payload)
                })
                .or_else(|_| {
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, payload)
                });

        match decoded {
            Ok(bytes) if bytes.len() >= 32 => ChecksumResult::Valid,
            Ok(_) => ChecksumResult::Invalid,
            Err(_) => ChecksumResult::Invalid,
        }
    }
}
