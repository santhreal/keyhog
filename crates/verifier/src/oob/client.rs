//! Low-level interactsh protocol client.
//!
//! A thin async wrapper around the projectdiscovery/interactsh-server register/
//! poll/deregister endpoints. Stateless aside from the RSA keypair, secret,
//! correlation id, and HTTP client — `OobSession` (in `session.rs`) layers
//! the per-finding subscription, polling loop, and notification fan-out on top.
//!
//! ## Crypto invariants
//!
//! - RSA-2048, OAEP padding, SHA-256 hash and MGF — interactsh-server speaks
//!   exactly this combination; `RSA_PKCS1_OAEP_PADDING` with SHA-256 in their
//!   Go code. Other parameters won't decrypt.
//! - AES-256-CFB with a 16-byte IV prepended to ciphertext. Each interaction
//!   carries an independent IV; the AES key is per-poll-batch.
//! - We never log credentials, public keys, or decrypted payloads. Errors
//!   carry stable strings — useful for support, opaque to leaks.

use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand::distributions::Alphanumeric;
use rand::{rngs::OsRng, Rng};
use reqwest::Client;
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use tracing::{debug, warn};

use aes::Aes256;
use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
type Aes256CfbDec = cfb_mode::Decryptor<Aes256>;

/// All errors that can arise from the OOB client. `Transient` errors mean the
/// caller should retry (network blip, rate-limit); everything else is final.
#[derive(Debug, Error)]
pub enum InteractshError {
    #[error("interactsh keypair generation failed: {0}")]
    KeyGen(String),
    #[error("interactsh public-key encoding failed: {0}")]
    KeyEncode(String),
    #[error("interactsh register failed (HTTP {status}): {body}")]
    Register { status: u16, body: String },
    #[error("interactsh poll failed (HTTP {status}): {body}")]
    Poll { status: u16, body: String },
    #[error("interactsh response shape unexpected: {0}")]
    BadResponse(String),
    #[error("interactsh AES key unwrap failed: {0}")]
    AesUnwrap(String),
    #[error("interactsh interaction decrypt failed: {0}")]
    Decrypt(String),
    #[error("interactsh transport error: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("interactsh request timed out after {0:?}")]
    Timeout(Duration),
}

/// Protocol category of a received interaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InteractionProtocol {
    Dns,
    Http,
    Smtp,
    Other,
}

impl InteractionProtocol {
    fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "dns" => Self::Dns,
            "http" => Self::Http,
            "smtp" | "smtp-mail" => Self::Smtp,
            _ => Self::Other,
        }
    }
}

/// One decrypted interaction returned by the collector.
#[derive(Debug, Clone)]
pub struct Interaction {
    /// Full 33-char unique id (correlation-id || 13-char suffix). This is
    /// what we match against per-finding URLs we minted.
    pub unique_id: String,
    pub protocol: InteractionProtocol,
    pub remote_address: String,
    pub timestamp: String,
    /// Raw protocol payload (HTTP request line + headers, DNS query, etc.).
    /// Sized — interactsh truncates server-side, but we cap to 16 KiB here as
    /// a defense-in-depth budget against memory abuse from a hostile server.
    pub raw_payload: String,
}

/// One interactsh registration. Cheap to clone (Arc-friendly fields only on
/// caller's side; here we hold owned values because the session pins this
/// for the lifetime of the engine).
pub struct InteractshClient {
    http: Client,
    server: String,
    correlation_id: String,
    secret_key: String,
    private_key: RsaPrivateKey,
    /// Length of the per-URL suffix (interactsh uses 13 to bring total ID to
    /// 33 chars). Exposed for tests; production always uses 13.
    suffix_len: usize,
}

impl InteractshClient {
    /// Test-only constructor that fabricates an `InteractshClient` without
    /// going through `register()`. The HTTP client is real but never used
    /// (tests drive the session directly via `store_and_notify_for_test`).
    /// The RSA keypair is generated locally so any decrypt-side test
    /// fixtures still see consistent crypto material.
    #[cfg(test)]
    pub(crate) fn for_test(server: &str) -> Self {
        let private_key = RsaPrivateKey::new(&mut OsRng, 1024).expect("test RSA key generates");
        Self {
            http: Client::new(),
            server: normalize_server(server),
            correlation_id: "abcdefghijklmnopqrst".to_string(),
            secret_key: "test-secret".to_string(),
            private_key,
            suffix_len: 13,
        }
    }
}

/// JSON shapes from interactsh-server. Field names match the upstream Go
/// definitions (`pkg/server/types.go`). `serde(default)` keeps us forward-
/// compatible with future fields.
#[derive(Serialize)]
struct RegisterRequest<'a> {
    #[serde(rename = "public-key")]
    public_key: &'a str,
    #[serde(rename = "secret-key")]
    secret_key: &'a str,
    #[serde(rename = "correlation-id")]
    correlation_id: &'a str,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct PollResponse {
    /// Each entry is base64( AES-256-CFB( IV[16] || ciphertext ) ).
    data: Vec<String>,
    /// Auxiliary metadata; ignored.
    #[allow(dead_code)]
    extra: Vec<String>,
    /// Base64( RSA-OAEP-SHA256( 32-byte AES key ) ). Server omits when there
    /// are no interactions; in that case `data` is also empty.
    aes_key: Option<String>,
}

/// Decrypted interaction shape. `serde(default)` because interactsh-server
/// sometimes ships partial events (failed protocol parse, etc.) and we'd
/// rather degrade gracefully than 500.
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

const MAX_RAW_PAYLOAD: usize = 16 * 1024;

/// Hard cap on the body of a `/poll` response. Protects the process from a
/// hostile or misbehaving collector returning a multi-gigabyte JSON that
/// would force `serde_json::from_slice` to allocate the whole thing
/// in-memory before we can validate it. 4 MiB comfortably fits any
/// reasonable poll batch — see the rationale at the call site.
const MAX_POLL_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Cap on error/diagnostic bodies. We only display the first 256 chars in
/// the error message anyway, but the cap prevents a server returning a
/// 500 with a 1 GiB body from spiking memory.
const ERROR_BODY_CAP: usize = 64 * 1024;

/// Stream a response body into a Vec under a hard byte cap. Returns
/// `BadResponse` if the cap is exceeded — abort the read rather than
/// trust the server's framing.
async fn read_capped_bytes(
    resp: reqwest::Response,
    cap: usize,
) -> Result<Vec<u8>, InteractshError> {
    use futures_util::StreamExt;
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(InteractshError::Transport)?;
        if buf.len().saturating_add(chunk.len()) > cap {
            return Err(InteractshError::BadResponse(format!(
                "response body exceeds {cap}-byte cap"
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Like `read_capped_bytes` but for diagnostic error messages — never
/// returns `Err`; on a stream failure or cap breach it returns whatever
/// was buffered so the error log can still surface something.
async fn read_capped_text(resp: reqwest::Response, cap: usize) -> String {
    use futures_util::StreamExt;
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let Ok(chunk) = chunk else { break };
        if buf.len().saturating_add(chunk.len()) > cap {
            break;
        }
        buf.extend_from_slice(&chunk);
    }
    String::from_utf8_lossy(&buf).into_owned()
}

impl InteractshClient {
    /// Build, generate keys, and register with the collector. The returned
    /// client is ready to mint URLs and be polled.
    pub async fn register(http: Client, server: &str) -> Result<Self, InteractshError> {
        // RSA-2048 keygen happens on a blocking thread — it's CPU-bound for
        // ~100ms and would otherwise stall the runtime.
        let private_key = tokio::task::spawn_blocking(|| {
            RsaPrivateKey::new(&mut OsRng, 2048).map_err(|e| InteractshError::KeyGen(e.to_string()))
        })
        .await
        .map_err(|e| InteractshError::KeyGen(format!("join error: {e}")))??;

        let public_key = RsaPublicKey::from(&private_key);
        let pem = public_key
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| InteractshError::KeyEncode(e.to_string()))?;
        let public_key_b64 = B64.encode(pem.as_bytes());

        // Correlation id is 20 lowercase alphanumerics — interactsh-server
        // matches incoming subdomains by this prefix, so the ID space must
        // be wide enough that collisions are statistically impossible across
        // every concurrent scanner sharing the collector. 36^20 ≈ 1.3e31.
        let correlation_id: String = OsRng
            .sample_iter(&Alphanumeric)
            .take(20)
            .map(|b| (b as char).to_ascii_lowercase())
            .collect();
        let secret_key = uuid::Uuid::new_v4().to_string();

        let server = normalize_server(server);

        let body = RegisterRequest {
            public_key: &public_key_b64,
            secret_key: &secret_key,
            correlation_id: &correlation_id,
        };
        let resp = http
            .post(format!("{server}/register"))
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = read_capped_text(resp, ERROR_BODY_CAP).await;
            return Err(InteractshError::Register {
                status: status.as_u16(),
                body: body.chars().take(256).collect(),
            });
        }
        // Drain (and discard) the register success body under a cap. Some
        // interactsh deployments echo registration metadata; we don't need
        // it but must not let the connection sit half-read indefinitely.
        let _ = read_capped_bytes(resp, ERROR_BODY_CAP).await;
        debug!(target: "keyhog::oob", correlation_id = %correlation_id, server = %server, "registered with interactsh collector");

        Ok(Self {
            http,
            server,
            correlation_id,
            secret_key,
            private_key,
            suffix_len: 13,
        })
    }

    /// Mint a fresh callback URL bound to this session. The full 33-char
    /// subdomain is returned (unique-id) plus the host the service should
    /// hit. Caller is responsible for embedding it where the credential's
    /// API will follow.
    pub fn mint_url(&self) -> MintedUrl {
        let suffix: String = OsRng
            .sample_iter(&Alphanumeric)
            .take(self.suffix_len)
            .map(|b| (b as char).to_ascii_lowercase())
            .collect();
        let unique_id = format!("{}{}", self.correlation_id, suffix);
        let host = format!("{}.{}", unique_id, self.server_host());
        let url = format!("https://{host}");
        MintedUrl {
            unique_id,
            host,
            url,
        }
    }

    /// Poll once. Returns every interaction the collector has buffered for
    /// this correlation id since the last poll.
    pub async fn poll(&self) -> Result<Vec<Interaction>, InteractshError> {
        let resp = self
            .http
            .get(format!("{}/poll", self.server))
            .query(&[("id", &self.correlation_id), ("secret", &self.secret_key)])
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = read_capped_text(resp, ERROR_BODY_CAP).await;
            return Err(InteractshError::Poll {
                status: status.as_u16(),
                body: body.chars().take(256).collect(),
            });
        }
        // Bound the response body before deserialization. A malicious or
        // misbehaving collector could otherwise blow process memory by
        // returning a multi-gigabyte JSON. 4 MiB comfortably fits even a
        // dense poll batch (≤100 interactions × ~16 KiB raw_payload each
        // base64-expanded ≈ 2 MiB) with headroom.
        let body = read_capped_bytes(resp, MAX_POLL_BODY_BYTES).await?;
        let parsed: PollResponse = serde_json::from_slice(&body)
            .map_err(|e| InteractshError::BadResponse(e.to_string()))?;
        if parsed.data.is_empty() {
            return Ok(Vec::new());
        }
        let aes_key_b64 = parsed.aes_key.ok_or_else(|| {
            InteractshError::BadResponse("data present but aes_key missing".into())
        })?;
        let aes_key = self.unwrap_aes_key(&aes_key_b64)?;
        if aes_key.len() != 32 {
            return Err(InteractshError::AesUnwrap(format!(
                "expected 32-byte AES-256 key, got {}",
                aes_key.len()
            )));
        }

        let mut out = Vec::with_capacity(parsed.data.len());
        for entry in parsed.data {
            match decrypt_entry(&aes_key, &entry) {
                Ok(Some(interaction)) => out.push(interaction),
                Ok(None) => {} // unparseable JSON — skip, don't fail the batch
                Err(e) => {
                    warn!(target: "keyhog::oob", error = %e, "interactsh entry decrypt failed; skipping")
                }
            }
        }
        Ok(out)
    }

    /// Tear down the registration. Idempotent on the server side; a failure
    /// to deregister is non-fatal — the server prunes inactive sessions
    /// after its retention window.
    pub async fn deregister(&self) -> Result<(), InteractshError> {
        #[derive(Serialize)]
        struct DeregisterRequest<'a> {
            #[serde(rename = "correlation-id")]
            correlation_id: &'a str,
            #[serde(rename = "secret-key")]
            secret_key: &'a str,
        }
        let _ = self
            .http
            .post(format!("{}/deregister", self.server))
            .json(&DeregisterRequest {
                correlation_id: &self.correlation_id,
                secret_key: &self.secret_key,
            })
            .send()
            .await?;
        Ok(())
    }

    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }

    /// `oast.fun` from `https://oast.fun/`.
    fn server_host(&self) -> &str {
        // strip scheme; we normalized at register time so no path component.
        self.server
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(&self.server)
            .trim_end_matches('/')
    }

    fn unwrap_aes_key(&self, b64: &str) -> Result<Vec<u8>, InteractshError> {
        let wrapped = B64
            .decode(b64.as_bytes())
            .map_err(|e| InteractshError::AesUnwrap(format!("base64: {e}")))?;
        let padding = Oaep::new::<Sha256>();
        self.private_key
            .decrypt(padding, &wrapped)
            .map_err(|e| InteractshError::AesUnwrap(format!("rsa-oaep: {e}")))
    }
}

/// One per-finding callback URL, returned from `InteractshClient::mint_url`.
#[derive(Debug, Clone)]
pub struct MintedUrl {
    /// Full 33-char id; the value the service will reflect in DNS/HTTP host.
    pub unique_id: String,
    /// `<unique_id>.<server-host>` — bare host without scheme.
    pub host: String,
    /// `https://<host>` — convenience for HTTP-shaped probes.
    pub url: String,
}

fn decrypt_entry(aes_key: &[u8], b64: &str) -> Result<Option<Interaction>, InteractshError> {
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

/// Accept `oast.fun`, `oast.fun/`, `https://oast.fun`, `https://oast.fun/`.
/// Always return `https://<host>` with no trailing slash. HTTP-only is
/// rejected because the AES key flowing back must travel TLS-wrapped.
fn normalize_server(s: &str) -> String {
    let s = s.trim().trim_end_matches('/');
    if let Some(rest) = s.strip_prefix("http://") {
        // Force-upgrade. We never speak plaintext to a collector — the
        // wrapped AES key would leak otherwise.
        format!("https://{rest}")
    } else if s.starts_with("https://") {
        s.to_string()
    } else {
        format!("https://{s}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_server_forces_https() {
        assert_eq!(normalize_server("oast.fun"), "https://oast.fun");
        assert_eq!(normalize_server("oast.fun/"), "https://oast.fun");
        assert_eq!(normalize_server("https://oast.fun"), "https://oast.fun");
        assert_eq!(normalize_server("http://oast.fun"), "https://oast.fun");
        assert_eq!(normalize_server("  https://oast.fun/ "), "https://oast.fun");
    }

    #[test]
    fn protocol_parse_is_case_insensitive() {
        assert_eq!(InteractionProtocol::parse("DNS"), InteractionProtocol::Dns);
        assert_eq!(
            InteractionProtocol::parse("Http"),
            InteractionProtocol::Http
        );
        assert_eq!(
            InteractionProtocol::parse("smtp-mail"),
            InteractionProtocol::Smtp
        );
        assert_eq!(
            InteractionProtocol::parse("websocket"),
            InteractionProtocol::Other
        );
    }

    /// End-to-end crypto round trip with a fixed AES key + IV. Mirrors what
    /// the server does: AES-256-CFB encrypt a JSON blob, prepend IV, base64.
    /// We then run our decrypt path and confirm the parsed Interaction.
    #[test]
    fn decrypt_entry_round_trip() {
        use aes::Aes256;
        use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
        type Enc = cfb_mode::Encryptor<Aes256>;

        let aes_key = [0x42u8; 32];
        let iv = [0x17u8; 16];
        let payload = serde_json::json!({
            "protocol": "http",
            "unique-id": "abcdefghijklmnopqrstuvwxyz0123456",
            "full-id":   "abcdefghijklmnopqrstuvwxyz0123456",
            "remote-address": "203.0.113.7",
            "timestamp": "2026-05-06T00:00:00Z",
            "raw-request": "GET /x HTTP/1.1\r\nHost: abc...example\r\n\r\n",
        })
        .to_string();
        let mut buf = payload.as_bytes().to_vec();
        Enc::new_from_slices(&aes_key, &iv)
            .unwrap()
            .encrypt(&mut buf);

        let mut wire = Vec::with_capacity(16 + buf.len());
        wire.extend_from_slice(&iv);
        wire.extend_from_slice(&buf);
        let b64 = B64.encode(&wire);

        let interaction = decrypt_entry(&aes_key, &b64).unwrap().unwrap();
        assert_eq!(interaction.unique_id.len(), 33);
        assert_eq!(interaction.protocol, InteractionProtocol::Http);
        assert_eq!(interaction.remote_address, "203.0.113.7");
        assert!(interaction.raw_payload.starts_with("GET /x"));
    }

    #[test]
    fn decrypt_entry_rejects_short_ciphertext() {
        let err = decrypt_entry(&[0u8; 32], &B64.encode([1u8; 8])).unwrap_err();
        match err {
            InteractshError::Decrypt(msg) => assert!(msg.contains("too short")),
            other => panic!("expected Decrypt, got {other:?}"),
        }
    }

    #[test]
    fn decrypt_entry_skips_invalid_json() {
        // Garbage that decrypts to non-JSON bytes (with a real AES key it'd be
        // junk; with all-zero key + IV the plaintext is just the ciphertext
        // XOR-pattern, which won't parse). Either way, we expect Ok(None),
        // never a hard failure that aborts the whole poll batch.
        let aes_key = [0u8; 32];
        let iv = [0u8; 16];
        let mut buf = b"definitely not json {{{".to_vec();
        use aes::Aes256;
        use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
        type Enc = cfb_mode::Encryptor<Aes256>;
        Enc::new_from_slices(&aes_key, &iv)
            .unwrap()
            .encrypt(&mut buf);
        let mut wire = iv.to_vec();
        wire.extend_from_slice(&buf);
        let b64 = B64.encode(&wire);
        assert!(decrypt_entry(&aes_key, &b64).unwrap().is_none());
    }
}
