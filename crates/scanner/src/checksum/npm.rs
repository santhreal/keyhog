use super::github::{base62_encode_u32, crc32};
use super::{ChecksumResult, ChecksumValidator};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;

/// Validates modern npm access tokens.
///
/// New-format npm tokens follow the same design as GitHub tokens:
/// `npm_` + 30-character entropy + 6-character base62 CRC32 checksum.
pub(crate) struct NpmTokenValidator;

/// npm token body layout: entropy chars followed by a base62 CRC32 checksum.
/// The total body length is derived from the parts so the length gate and the
/// entropy/checksum slice boundary can never disagree.
const NPM_ENTROPY_LEN: usize = 30;
const NPM_CHECKSUM_LEN: usize = 6;
const NPM_BODY_LEN: usize = NPM_ENTROPY_LEN + NPM_CHECKSUM_LEN;

impl ChecksumValidator for NpmTokenValidator {
    fn validate(&self, credential: &str) -> ChecksumResult {
        let payload = match credential.strip_prefix(super::prefixes::NPM_ACCESS_TOKEN) {
            Some(p) => p,
            None => return ChecksumResult::NotApplicable,
        };
        if payload.len() != NPM_BODY_LEN {
            return ChecksumResult::NotApplicable;
        }
        if !payload.chars().all(|c| c.is_ascii_alphanumeric()) {
            return ChecksumResult::Invalid;
        }
        let entropy = &payload[..NPM_ENTROPY_LEN];
        let checksum_str = &payload[NPM_ENTROPY_LEN..];
        let expected = base62_encode_u32(crc32(entropy.as_bytes()), NPM_CHECKSUM_LEN);
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
pub(crate) struct PypiTokenValidator;

impl ChecksumValidator for PypiTokenValidator {
    fn validate(&self, credential: &str) -> ChecksumResult {
        let payload = match credential.strip_prefix(super::prefixes::PYPI_API_TOKEN) {
            Some(p) => p,
            None => return ChecksumResult::NotApplicable,
        };
        if payload.len() < 20 {
            return ChecksumResult::Invalid;
        }
        match decode_pypi_payload(payload) {
            Ok(bytes) if bytes.len() >= 32 => ChecksumResult::Valid,
            Ok(_) => ChecksumResult::Invalid,
            Err(_) => ChecksumResult::Invalid, // LAW10: decode failure => Invalid; structural precision gate (a matched-shape payload that will not decode is not the real token), fail-closed
        }
    }
}

fn decode_pypi_payload(payload: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let mut has_url_safe_alphabet = false;
    let mut has_standard_alphabet = false;
    let mut has_padding = false;
    for &byte in payload.as_bytes() {
        match byte {
            b'-' | b'_' => has_url_safe_alphabet = true,
            b'+' | b'/' => has_standard_alphabet = true,
            b'=' => has_padding = true,
            _ => {}
        }
    }

    if has_url_safe_alphabet && has_standard_alphabet {
        return Err(base64::DecodeError::InvalidByte(0, b'?'));
    }

    match (has_url_safe_alphabet, has_padding) {
        (true, true) => URL_SAFE.decode(payload),
        (true, false) => URL_SAFE_NO_PAD.decode(payload),
        (false, true) => STANDARD.decode(payload),
        (false, false) => STANDARD_NO_PAD.decode(payload),
    }
}
