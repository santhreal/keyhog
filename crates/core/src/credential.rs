//! Opaque, zeroize-on-drop credential bytes.
//!
//! Debt bucket (`#![allow(missing_docs)]` below): 7 items predating the crate
//! floor raising `missing_docs` to `warn`. Remove once each carries a doc.
//!
//! Replaces the previous `Arc<str>` credential field with a type that:
//!
//! 1. Zeroes its bytes on drop (`zeroize` crate). Heap pages keyhog freed
//!    while a scan was in flight no longer leak credentials to the next
//!    allocator request, swap, or post-mortem core dump.
//! 2. Refuses `Debug` / `Display` printing - every leak path through `{:?}`
//!    or `{}` becomes `<redacted N bytes>` instead of the bytes themselves.
//!    To get the bytes you must call `expose_secret()` explicitly, which
//!    grep'ing the codebase for can audit every credential touch site.
//! 3. Is `Clone` and serializable via `serde` (uses the `expose_secret()`
//!    bytes for `Serialize`, decodes back to a fresh `Credential` for
//!    `Deserialize`). The serialization channel is the responsibility of
//!    the caller - find emitters that go to disk/JSON and either redact
//!    them or wrap the entire output in EnvSeal seal.
//!
//! When EnvSeal embeds keyhog, this type is the only place credential
//! bytes ever appear in process memory; an mlock + memfd backing can be
//! added behind the `lockdown` feature gate without touching call sites.

#![allow(missing_docs)]

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
    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            inner: Arc::new(Zeroizing::new(bytes.to_vec().into_boxed_slice())),
        }
    }

    /// Build a `Credential` from a borrowed `str`. Same semantics as
    /// `from_bytes` - bytes are copied into the zeroizing allocation.
    /// Named `from_text` (not `from_str`) to avoid the
    /// `clippy::should_implement_trait` lint and to keep the API
    /// distinct from `core::str::FromStr` (which has different error
    /// semantics - we never fail to construct a Credential).
    #[must_use]
    pub(crate) fn from_text(s: &str) -> Self {
        Self::from_bytes(s.as_bytes())
    }

    /// Expose the underlying bytes. Every call site MUST be auditable -
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
    pub(crate) fn expose_str(&self) -> Option<&str> {
        // The `Option<&str>` return IS the loud surface: a non-UTF-8 credential
        // (raw key bytes, binary token) maps to `None`, which every caller must
        // handle, and the raw bytes remain available via `expose_secret()`.
        std::str::from_utf8(&self.inner).ok() // LAW10: Option return is the surface, raw bytes kept via expose_secret(), see note
    }
}

impl From<&str> for Credential {
    fn from(s: &str) -> Self {
        Self::from_text(s)
    }
}

impl From<String> for Credential {
    fn from(s: String) -> Self {
        // The input `String`'s buffer is dropped without zeroizing - the
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
    /// Refuse to format the bytes. This is a compile-time leak guard -
    /// every place that did `eprintln!("{:?}", cred)` or `tracing::error!(?cred)`
    /// now prints `Credential(<redacted N bytes>)` instead of the secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Credential(<redacted {} bytes>)", self.inner.len())
    }
}

impl std::fmt::Display for Credential {
    /// Same redaction as `Debug` - `format!("{}", cred)` returns the
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
            None => {
                m.serialize_entry("b64", &crate::encoding::encode_standard_base64(&self.inner))?
            }
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
                let bytes = crate::encoding::decode_standard_base64(&b)
                    .map_err(serde::de::Error::custom)?;
                Ok(Credential::from_bytes(&bytes))
            }
            Wire::Tagged { .. } => Err(serde::de::Error::custom(
                "Credential must specify exactly one of `text` or `b64`",
            )),
            Wire::Legacy(s) => {
                if let Some(rest) = s.strip_prefix("b64:") {
                    let bytes = crate::encoding::decode_standard_base64(rest)
                        .map_err(serde::de::Error::custom)?;
                    Ok(Credential::from_bytes(&bytes))
                } else {
                    Ok(Credential::from_text(&s))
                }
            }
        }
    }
}

/// A heap-allocated string that is zeroized on drop.
#[derive(Clone, Default)]
pub struct SensitiveString {
    inner: Arc<Zeroizing<String>>,
}

impl SensitiveString {
    fn new(s: String) -> Self {
        Self {
            inner: Arc::new(Zeroizing::new(s)),
        }
    }

    pub fn join(parts: &[SensitiveString], sep: &str) -> Self {
        let mut s = String::new();
        for (i, p) in parts.iter().enumerate() {
            if i > 0 {
                s.push_str(sep);
            }
            s.push_str(p.as_str());
        }
        Self::new(s)
    }

    pub(crate) fn as_str(&self) -> &str {
        self.inner.as_str()
    }
}

impl std::ops::Deref for SensitiveString {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl AsRef<str> for SensitiveString {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::borrow::Borrow<str> for SensitiveString {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl PartialEq for SensitiveString {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for SensitiveString {}

impl PartialOrd for SensitiveString {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SensitiveString {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl Hash for SensitiveString {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

impl From<String> for SensitiveString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for SensitiveString {
    fn from(s: &str) -> Self {
        Self::new(s.to_string())
    }
}

impl From<&String> for SensitiveString {
    fn from(s: &String) -> Self {
        Self::new(s.clone())
    }
}

impl std::fmt::Display for SensitiveString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::fmt::Debug for SensitiveString {
    /// Refuse to print the inner string. `SensitiveString` backs scan-chunk
    /// data (`Chunk::data`), which can contain raw credential material -
    /// decoded secrets, `.env` lines, archive-entry bytes. The previous impl
    /// emitted `SensitiveString("<raw content>")`, leaking those bytes into
    /// any `{:?}` print, `tracing::debug!(?chunk)` span, or panic message.
    /// Mirror the `Credential::Debug` byte-count redaction (kimi-wave1
    /// finding 1.1). Note: `Display` intentionally still exposes the bytes -
    /// callers that genuinely need the content format with `{}`, which is the
    /// auditable surface; `{:?}` must never be one.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SensitiveString(<redacted {} bytes>)", self.inner.len())
    }
}

impl Serialize for SensitiveString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.as_str().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SensitiveString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}
