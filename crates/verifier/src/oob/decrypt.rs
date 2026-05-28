//! AES-256-CFB decrypt of a single interactsh-server poll entry.
//!
//! Extracted from `oob/client.rs` so the client module stays under the
//! 500-line modularity cap. The split is along the natural seam: the
//! client owns RSA key state + HTTP I/O, and this file owns the per-
//! entry symmetric-decrypt path that turns each base64 ciphertext into
//! an `Interaction`.

use aes::Aes256;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
use serde::Deserialize;
use tracing::debug;

use super::client::{Interaction, InteractionProtocol, InteractshError};

type Aes256CfbDec = cfb_mode::Decryptor<Aes256>;

/// Upstream interactsh-server interaction shape. `serde(default)` keeps
/// the deserializer tolerant to new fields the server adds - every
/// unrecognized key is dropped, every missing key falls to its
/// type-default. Field renames match the Go upstream `pkg/server/types.go`.
#[derive(Deserialize, Default)]
#[serde(default)]
struct InteractionRaw {
    protocol: String,
    #[serde(rename = "unique-id")]
    unique_id: String,
    #[serde(rename = "full-id")]
    full_id: String,
    #[serde(rename = "remote-address")]
    remote_address: String,
    timestamp: String,
    #[serde(rename = "raw-request")]
    raw_request: String,
    #[serde(rename = "raw-response")]
    raw_response: String,
    #[serde(rename = "q-type")]
    q_type: String,
}

/// Hard cap on the raw_request/raw_response/q_type payload size we
/// retain per interaction. interactsh occasionally surfaces multi-MB
/// HTTP bodies (think a buggy probe POSTing a logfile); we don't need
/// those at finding granularity and they'd bloat the observation cache
/// and any UI surface. 16 KiB is generous for the diagnostic windows
/// the verifier renders.
const MAX_RAW_PAYLOAD: usize = 16 * 1024;

pub(super) fn decrypt_entry(
    aes_key: &[u8],
    b64: &str,
) -> Result<Option<Interaction>, InteractshError> {
    let bytes = B64
        .decode(b64.as_bytes())
        .map_err(|e| InteractshError::Decrypt(format!("base64: {e}")))?;
    if bytes.len() < 16 {
        return Err(InteractshError::Decrypt(format!(
            "ciphertext too short ({} < 16)",
            bytes.len()
        )));
    }
    let (iv, ct) = bytes.split_at(16);
    let mut buf = ct.to_vec();
    Aes256CfbDec::new_from_slices(aes_key, iv)
        .map_err(|e| InteractshError::Decrypt(format!("cfb init: {e}")))?
        .decrypt(&mut buf);
    let json = match std::str::from_utf8(&buf) {
        Ok(s) => s,
        Err(_) => return Ok(None), // server hiccup; don't blow up the poll
    };
    let raw: InteractionRaw = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(e) => {
            debug!(target: "keyhog::oob", error = %e, "interactsh JSON parse failed; skipping entry");
            return Ok(None);
        }
    };
    let unique_id = if !raw.full_id.is_empty() {
        raw.full_id
    } else {
        raw.unique_id
    };
    if unique_id.is_empty() {
        return Ok(None);
    }
    // Prefer raw_request; fall back to raw_response then q_type so DNS-only
    // interactions still carry diagnostic detail.
    let raw_payload = if !raw.raw_request.is_empty() {
        raw.raw_request
    } else if !raw.raw_response.is_empty() {
        raw.raw_response
    } else {
        raw.q_type
    };
    let raw_payload: String = raw_payload.chars().take(MAX_RAW_PAYLOAD).collect();
    Ok(Some(Interaction {
        unique_id,
        protocol: InteractionProtocol::parse(&raw.protocol),
        remote_address: raw.remote_address,
        timestamp: raw.timestamp,
        raw_payload,
    }))
}
