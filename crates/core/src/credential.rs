//! Opaque, zeroize-on-drop credential bytes.
//!
//! Replaces the previous `Arc<str>` credential field with a type that:
//!
//! 1. Zeroes its bytes on drop (`zeroize` crate). Heap pages keyhog freed
//!    while a scan was in flight no longer leak credentials to the next
//!    allocator request, swap, or post-mortem core dump.
//! 2. Refuses `Debug` / `Display` printing — every leak path through `{:?}`
//!    or `{}` becomes `<redacted N bytes>` instead of the bytes themselves.
//!    To get the bytes you must call `expose_secret()` explicitly, which
//!    grep'ing the codebase for can audit every credential touch site.
//! 3. Is `Clone` and serializable via `serde` (uses the `expose_secret()`
//!    bytes for `Serialize`, decodes back to a fresh `Credential` for
//!    `Deserialize`). The serialization channel is the responsibility of
//!    the caller — find emitters that go to disk/JSON and either redact
//!    them or wrap the entire output in EnvSeal seal.
//!
//! When EnvSeal embeds keyhog, this type is the only place credential
//! bytes ever appear in process memory; an mlock + memfd backing can be
//! added behind the `lockdown` feature gate without touching call sites.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use zeroize::Zeroizing;

/// Opaque credential bytes. The inner `Arc<Zeroizing<Box<[u8]>>>` clones are
/// cheap (refcount bump) but every owning `Credential` zeroizes on drop.
/// `Arc` lets the engine intern identical credentials without copying;
/// when the last ref drops, `Zeroizing<Box<[u8]>>` overwrites the heap
/// allocation before `Box::drop` returns it to the allocator.
#[derive(Clone)]
pub struct Credential {
    inner: Arc<Zeroizing<Box<[u8]>>>,
}

impl Credential {
    /// Build a `Credential` from raw bytes. The bytes are copied into a
    /// fresh `Zeroizing<Box<[u8]>>` and the input slice is unchanged
    /// (caller is responsible for zeroizing whatever it came from).
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            inner: Arc::new(Zeroizing::new(bytes.to_vec().into_boxed_slice())),
        }
    }

    /// Build a `Credential` from a borrowed `str`. Same semantics as
    /// `from_bytes` — bytes are copied into the zeroizing allocation.
    /// Named `from_text` (not `from_str`) to avoid the
    /// `clippy::should_implement_trait` lint and to keep the API
    /// distinct from `core::str::FromStr` (which has different error
    /// semantics — we never fail to construct a Credential).
    #[must_use]
    pub fn from_text(s: &str) -> Self {
        Self::from_bytes(s.as_bytes())
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Expose the underlying bytes. Every call site MUST be auditable —
    /// `git grep expose_secret` should surface every place credentials
    /// leave the opaque wrapper. Treat each one as a security review item.
    ///
    /// Returns a `&[u8]` rather than `&str` because credentials may be
    /// non-UTF-8 (binary-encoded keys, raw private-key bytes, etc).
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.inner
    }

    /// Expose the credential as a `&str` if it's valid UTF-8, otherwise
    /// `None`. Most production credentials ARE valid UTF-8 (provider keys,
    /// tokens, base64) so this is the common path.
    #[must_use]
    pub fn expose_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.inner).ok()
    }
}

impl From<&str> for Credential {
    fn from(s: &str) -> Self {
        Self::from_text(s)
    }
}

impl From<String> for Credential {
    fn from(s: String) -> Self {
        // The input `String`'s buffer is dropped without zeroizing — the
        // caller should ideally pass `&str` so the bytes never sit in a
        // non-zeroizing `String`. We do the right thing for our own
        // allocation either way.
        Self::from_bytes(s.as_bytes())
    }
}

impl From<&[u8]> for Credential {
    fn from(b: &[u8]) -> Self {
        Self::from_bytes(b)
    }
}

impl From<Vec<u8>> for Credential {
    fn from(v: Vec<u8>) -> Self {
        Self::from_bytes(&v)
    }
}

impl PartialEq for Credential {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time equality. Credentials are compared during dedup
        // and inflight de-duplication; using `==` on naked bytes leaks
        // information through CPU branch timing in pathological cases.
        // The cost is one extra XOR per byte vs `==`, negligible at the
        // sizes of credentials (<1 KiB typical).
        if self.inner.len() != other.inner.len() {
            return false;
        }
        let mut diff: u8 = 0;
        for (a, b) in self.inner.iter().zip(other.inner.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

impl Eq for Credential {}

impl PartialOrd for Credential {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Credential {
    fn cmp(&self, other: &Self) -> Ordering {
        self.inner
            .as_ref()
            .as_ref()
            .cmp(other.inner.as_ref().as_ref())
    }
}

impl Hash for Credential {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.as_ref().as_ref().hash(state);
    }
}

impl std::fmt::Debug for Credential {
    /// Refuse to format the bytes. This is a compile-time leak guard —
    /// every place that did `eprintln!("{:?}", cred)` or `tracing::error!(?cred)`
    /// now prints `Credential(<redacted N bytes>)` instead of the secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Credential(<redacted {} bytes>)", self.inner.len())
    }
}

impl std::fmt::Display for Credential {
    /// Same redaction as `Debug` — `format!("{}", cred)` returns the
    /// redacted form, never the bytes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<redacted {} bytes>", self.inner.len())
    }
}

impl Serialize for Credential {
    /// Serialize as a tagged JSON object so the encoding is unambiguous.
    /// kimi-wave2 §Critical: the previous `"b64:<base64>"` string-prefix
    /// scheme round-tripped a UTF-8 credential like `"b64:SGVsbG8="`
    /// (a literal user-typed value) through the deserializer as if it
    /// were base64-encoded bytes, silently corrupting it. The tagged
    /// variant `{"text":"…"}` / `{"b64":"…"}` cannot be confused with
    /// either form.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut m = serializer.serialize_map(Some(1))?;
        match self.expose_str() {
            Some(s) => m.serialize_entry("text", s)?,
            None => m.serialize_entry("b64", &base64_encode(&self.inner))?,
        }
        m.end()
    }
}

impl<'de> Deserialize<'de> for Credential {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Accept the new tagged form (preferred) OR the legacy
        // `b64:<base64>` / plain string forms (so on-disk artifacts
        // from earlier versions still load). The legacy ambiguity is
        // exactly what kimi-wave2 §Critical flagged; new writers must
        // use the tagged form.
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Tagged {
                #[serde(default)]
                text: Option<String>,
                #[serde(default)]
                b64: Option<String>,
            },
            Legacy(String),
        }
        match Wire::deserialize(deserializer)? {
            Wire::Tagged {
                text: Some(t),
                b64: None,
            } => Ok(Credential::from_text(&t)),
            Wire::Tagged {
                text: None,
                b64: Some(b),
            } => {
                let bytes = base64_decode(&b).map_err(serde::de::Error::custom)?;
                Ok(Credential::from_bytes(&bytes))
            }
            Wire::Tagged { .. } => Err(serde::de::Error::custom(
                "Credential must specify exactly one of `text` or `b64`",
            )),
            Wire::Legacy(s) => {
                if let Some(rest) = s.strip_prefix("b64:") {
                    let bytes = base64_decode(rest).map_err(serde::de::Error::custom)?;
                    Ok(Credential::from_bytes(&bytes))
                } else {
                    Ok(Credential::from_text(&s))
                }
            }
        }
    }
}

/// Minimal base64 encoder/decoder so this module doesn't need a crate dep.
/// Used only on the rare non-UTF-8 credential path; performance is not
/// critical.
fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(b2 & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Result<u8, String> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(format!("invalid base64 char: {c:#x}")),
        }
    }
    let bytes = input.as_bytes();
    let stripped: Vec<u8> = bytes.iter().copied().take_while(|&c| c != b'=').collect();
    let mut out = Vec::with_capacity(stripped.len() * 3 / 4);
    for chunk in stripped.chunks(4) {
        let v0 = val(chunk[0])?;
        let v1 = val(*chunk.get(1).ok_or("truncated base64")?)?;
        out.push((v0 << 2) | (v1 >> 4));
        if let Some(&c2) = chunk.get(2) {
            let v2 = val(c2)?;
            out.push(((v1 & 0x0F) << 4) | (v2 >> 2));
            if let Some(&c3) = chunk.get(3) {
                let v3 = val(c3)?;
                out.push(((v2 & 0x03) << 6) | v3);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_bytes() {
        let c = Credential::from_text("AKIAIOSFODNN7EXAMPLE");
        let s = format!("{c:?}");
        assert!(s.contains("redacted"));
        assert!(!s.contains("AKIA"));
    }

    #[test]
    fn display_redacts_bytes() {
        let c = Credential::from_text("ghp_abcdef1234567890");
        let s = format!("{c}");
        assert!(s.contains("redacted"));
        assert!(!s.contains("ghp_"));
    }

    #[test]
    fn expose_secret_returns_bytes() {
        let c = Credential::from_text("hello");
        assert_eq!(c.expose_secret(), b"hello");
        assert_eq!(c.expose_str(), Some("hello"));
    }

    #[test]
    fn equality_constant_time() {
        let a = Credential::from_text("aaa");
        let b = Credential::from_text("aaa");
        let c = Credential::from_text("aab");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn serialize_utf8_credential_as_tagged_text() {
        // kimi-wave2 §Critical: the wire format is now an explicit tagged
        // object, NOT a string-with-prefix. The tag eliminates the
        // ambiguity where `"b64:SGVsbG8="` (a literal user-typed string)
        // round-tripped as base64-decoded bytes.
        let c = Credential::from_text("AKIA1234");
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(json, "{\"text\":\"AKIA1234\"}");
    }

    #[test]
    fn serialize_binary_credential_as_tagged_b64() {
        let c = Credential::from_bytes(&[0xFF, 0xFE, 0x00, 0x42]);
        let json = serde_json::to_string(&c).unwrap();
        assert!(
            json.starts_with("{\"b64\":\""),
            "expected tagged b64 envelope, got {json}"
        );
    }

    #[test]
    fn legacy_b64_prefix_still_deserializes() {
        // Backwards compat: on-disk artifacts written by older keyhog
        // versions used the `"b64:<base64>"` string form. The new
        // deserializer falls back to that path.
        let bytes = [0xFF, 0xFE, 0x00, 0x42];
        let legacy = format!("\"b64:{}\"", super::base64_encode(&bytes));
        let back: Credential = serde_json::from_str(&legacy).unwrap();
        assert_eq!(back.expose_secret(), &bytes);
    }

    #[test]
    fn legacy_plain_string_still_deserializes() {
        let back: Credential = serde_json::from_str("\"AKIA1234\"").unwrap();
        assert_eq!(back.expose_str(), Some("AKIA1234"));
    }

    #[test]
    fn round_trip_serde() {
        let c = Credential::from_text("xoxb-1234-5678-abc");
        let json = serde_json::to_string(&c).unwrap();
        let back: Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn round_trip_binary_serde() {
        let c = Credential::from_bytes(&[0x00, 0x01, 0xFF, 0xFE]);
        let json = serde_json::to_string(&c).unwrap();
        let back: Credential = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn cloning_does_not_duplicate_buffer() {
        let a = Credential::from_text("shared");
        let b = a.clone();
        // Same Arc backing; addresses match.
        assert!(std::ptr::eq(
            a.expose_secret().as_ptr(),
            b.expose_secret().as_ptr()
        ));
    }
}
