use super::encode_parts::{MAGIC, MAX_PART_COUNT, MAX_SERIALIZED_PART_BYTES};
use vyre_driver::error::{Error, Result};

/// Decode a blob produced by `super::encode_parts`.
///
/// # Errors
///
/// Returns an actionable error when the frame header, length prefixes, or
/// declared payload sizes are invalid for this platform.
#[inline]
pub fn decode_parts(mut bytes: &[u8]) -> Result<Vec<&[u8]>> {
    if bytes.len() < MAGIC.len() || bytes[..MAGIC.len()] != MAGIC {
        return Err(Error::Gpu {
            message: "invalid vyre serializer header. Fix: pass data produced by encode_parts without trimming or prefixing bytes.".to_string(),
        });
    }
    bytes = &bytes[MAGIC.len()..];
    let mut parts = Vec::new();
    while !bytes.is_empty() {
        if parts.len() == MAX_PART_COUNT {
            return Err(Error::Serialization {
                message: format!(
                    "framed part count exceeds {MAX_PART_COUNT}. Fix: reject this frame or split the payload before framing."
                ),
            });
        }
        if bytes.len() < 8 {
            return Err(Error::Gpu {
                message: "truncated framed part length. Fix: provide all 8 bytes of each encoded part length.".to_string(),
            });
        }
        let raw_len = u64::from_le_bytes(bytes[..8].try_into().map_err(|source| Error::Serialization {
            message: format!("invalid framed part length: {source}. Fix: provide an intact 8-byte little-endian part length."),
        })?);
        let len = usize::try_from(raw_len).map_err(|source| Error::Serialization {
            message: format!("SerializationOverflow: framed part length {raw_len} cannot fit usize: {source}. Fix: reject this frame on this platform or split the payload."),
        })?;
        if len > MAX_SERIALIZED_PART_BYTES {
            return Err(Error::Serialization {
                message: format!(
                    "framed part declares {len} bytes, exceeding {MAX_SERIALIZED_PART_BYTES}. Fix: reject this frame or split the payload before framing."
                ),
            });
        }
        bytes = &bytes[8..];
        if bytes.len() < len {
            return Err(Error::Gpu {
                message: "truncated framed part payload. Fix: provide the full payload declared by the preceding length.".to_string(),
            });
        }
        let (part, rest) = bytes.split_at(len);
        parts.push(part);
        bytes = rest;
    }
    Ok(parts)
}
