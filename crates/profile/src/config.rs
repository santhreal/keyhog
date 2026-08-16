//! Profile configuration models, sensitive string protection, and zero-allocation profile lookup.
//!
//! Provides [`ProfileConfig`] for configuring execution profiles and telemetry,
//! [`SensitiveString`] for zeroize-on-drop token and credential protection, and
//! zero-allocation lookup routines for known profile names.

use std::borrow::{Borrow, Cow};
use std::collections::HashMap;
use std::fmt;
use std::ops::Deref;
use std::sync::Arc;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::Detail;

/// Timing-safe byte slice comparison.
///
/// Returns true if and only if both byte slices have equal length and identical bytes.
/// Executes in constant time for slices of equal length without early termination.
#[inline]
#[must_use]
pub fn constant_time_bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// A heap-allocated string that is zeroized on drop.
///
/// Protects sensitive tokens, credentials, and header values in profile configurations.
/// Plaintext access is explicit via [`Self::as_str`] or [`Deref`]. Formatting via
/// [`fmt::Display`] and [`fmt::Debug`] emits redacted byte counts to prevent leaks in logs.
/// Implicit serde serialization fails closed.
#[derive(Clone, Default)]
pub struct SensitiveString {
    inner: Arc<Zeroizing<String>>,
}

impl SensitiveString {
    /// Create a new sensitive string wrapping the given string.
    #[must_use]
    pub fn new(s: String) -> Self {
        Self {
            inner: Arc::new(Zeroizing::new(s)),
        }
    }

    /// Create a new sensitive string from an existing [`Zeroizing<String>`].
    #[must_use]
    pub fn from_zeroizing(z: Zeroizing<String>) -> Self {
        Self { inner: Arc::new(z) }
    }

    /// Return the plaintext string slice.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }

    /// Return the length of the sensitive string in bytes.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Return true if the sensitive string is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Deref for SensitiveString {
    type Target = str;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl AsRef<str> for SensitiveString {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for SensitiveString {
    #[inline]
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl PartialEq for SensitiveString {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        constant_time_bytes_eq(self.as_str().as_bytes(), other.as_str().as_bytes())
    }
}

impl Eq for SensitiveString {}

impl PartialOrd for SensitiveString {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SensitiveString {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl std::hash::Hash for SensitiveString {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
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
        Self::new(s.to_owned())
    }
}

impl From<&String> for SensitiveString {
    fn from(s: &String) -> Self {
        Self::new(s.clone())
    }
}

impl From<Zeroizing<String>> for SensitiveString {
    fn from(z: Zeroizing<String>) -> Self {
        Self::from_zeroizing(z)
    }
}

impl fmt::Display for SensitiveString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<redacted {} bytes>", self.inner.len())
    }
}

impl fmt::Debug for SensitiveString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SensitiveString(<redacted {} bytes>)", self.inner.len())
    }
}

impl Zeroize for SensitiveString {
    fn zeroize(&mut self) {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.zeroize();
        } else {
            self.inner = Arc::new(Zeroizing::new(String::new()));
        }
    }
}

impl ZeroizeOnDrop for SensitiveString {}

impl Serialize for SensitiveString {
    fn serialize<S: Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom(
            "SensitiveString refuses implicit plaintext serialization; access as_str() explicitly for protected channels",
        ))
    }
}

impl<'de> Deserialize<'de> for SensitiveString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SensitiveVisitor;

        impl<'de> Visitor<'de> for SensitiveVisitor {
            type Value = SensitiveString;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a sensitive string")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                let mut z = Zeroizing::new(String::with_capacity(v.len()));
                z.push_str(v);
                Ok(SensitiveString::from_zeroizing(z))
            }

            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                let z = Zeroizing::new(v);
                Ok(SensitiveString::from_zeroizing(z))
            }
        }

        deserializer.deserialize_string(SensitiveVisitor)
    }
}

/// Standard predefined profile identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum KnownProfile {
    /// Default standard execution profile.
    Default,
    /// Lean continuous integration profile.
    Ci,
    /// Optimized release profile.
    Release,
    /// Fast release profile for CI test runners.
    ReleaseFast,
    /// Debug profile with maximum runtime diagnostics.
    Debug,
    /// Development profile.
    Dev,
    /// Benchmark profiling profile.
    Bench,
    /// Portable profile without native accelerator dependencies.
    Portable,
    /// Deep scanning profile with exhaustive decoders.
    Deep,
    /// High-precision profile with strict confidence filtering.
    Precision,
    /// Test execution profile.
    Test,
    /// Staging environment profile.
    Staging,
    /// Production environment profile.
    Production,
}

impl KnownProfile {
    /// Return the canonical static string for the known profile.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Ci => "ci",
            Self::Release => "release",
            Self::ReleaseFast => "release-fast",
            Self::Debug => "debug",
            Self::Dev => "dev",
            Self::Bench => "bench",
            Self::Portable => "portable",
            Self::Deep => "deep",
            Self::Precision => "precision",
            Self::Test => "test",
            Self::Staging => "staging",
            Self::Production => "production",
        }
    }

    /// Resolve a known profile name from a string slice without heap allocations.
    /// Performs ASCII case-insensitive comparison and recognizes common aliases.
    #[must_use]
    pub fn from_str_case_insensitive(s: &str) -> Option<Self> {
        let trimmed = s.trim();
        if trimmed.eq_ignore_ascii_case("default") {
            Some(Self::Default)
        } else if trimmed.eq_ignore_ascii_case("ci") {
            Some(Self::Ci)
        } else if trimmed.eq_ignore_ascii_case("release") {
            Some(Self::Release)
        } else if trimmed.eq_ignore_ascii_case("release-fast")
            || trimmed.eq_ignore_ascii_case("release_fast")
            || trimmed.eq_ignore_ascii_case("releasefast")
        {
            Some(Self::ReleaseFast)
        } else if trimmed.eq_ignore_ascii_case("debug") {
            Some(Self::Debug)
        } else if trimmed.eq_ignore_ascii_case("dev") || trimmed.eq_ignore_ascii_case("development")
        {
            Some(Self::Dev)
        } else if trimmed.eq_ignore_ascii_case("bench") || trimmed.eq_ignore_ascii_case("benchmark")
        {
            Some(Self::Bench)
        } else if trimmed.eq_ignore_ascii_case("portable") {
            Some(Self::Portable)
        } else if trimmed.eq_ignore_ascii_case("deep") {
            Some(Self::Deep)
        } else if trimmed.eq_ignore_ascii_case("precision") {
            Some(Self::Precision)
        } else if trimmed.eq_ignore_ascii_case("test") {
            Some(Self::Test)
        } else if trimmed.eq_ignore_ascii_case("staging") {
            Some(Self::Staging)
        } else if trimmed.eq_ignore_ascii_case("production") || trimmed.eq_ignore_ascii_case("prod")
        {
            Some(Self::Production)
        } else {
            None
        }
    }
}

impl fmt::Display for KnownProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for KnownProfile {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Profile identifier supporting known profiles with zero heap allocations or custom names.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProfileName {
    /// Standard predefined profile backed by static memory.
    Known(KnownProfile),
    /// Custom user-defined profile name.
    Custom(Cow<'static, str>),
}

impl ProfileName {
    /// Return the profile name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Known(k) => k.as_str(),
            Self::Custom(c) => c.as_ref(),
        }
    }

    /// Parse a profile name from a string slice without heap allocations if known.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        if let Some(known) = KnownProfile::from_str_case_insensitive(s) {
            Self::Known(known)
        } else {
            Self::Custom(Cow::Owned(s.trim().to_owned()))
        }
    }

    /// Construct a profile name from a static string slice with zero heap allocations.
    #[must_use]
    pub fn from_static(s: &'static str) -> Self {
        if let Some(known) = KnownProfile::from_str_case_insensitive(s) {
            Self::Known(known)
        } else {
            Self::Custom(Cow::Borrowed(s))
        }
    }

    /// Return true if this names a standard predefined profile.
    #[must_use]
    pub const fn is_known(&self) -> bool {
        matches!(self, Self::Known(_))
    }

    /// Return the known profile variant if this is a standard profile.
    #[must_use]
    pub const fn as_known(&self) -> Option<KnownProfile> {
        match self {
            Self::Known(k) => Some(*k),
            Self::Custom(_) => None,
        }
    }
}

impl Default for ProfileName {
    fn default() -> Self {
        Self::Known(KnownProfile::Default)
    }
}

impl fmt::Display for ProfileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Deref for ProfileName {
    type Target = str;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl AsRef<str> for ProfileName {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for ProfileName {
    #[inline]
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl From<KnownProfile> for ProfileName {
    fn from(k: KnownProfile) -> Self {
        Self::Known(k)
    }
}

impl From<&'static str> for ProfileName {
    fn from(s: &'static str) -> Self {
        Self::from_static(s)
    }
}

impl From<String> for ProfileName {
    fn from(s: String) -> Self {
        if let Some(known) = KnownProfile::from_str_case_insensitive(&s) {
            Self::Known(known)
        } else {
            Self::Custom(Cow::Owned(s))
        }
    }
}

impl From<&String> for ProfileName {
    fn from(s: &String) -> Self {
        Self::parse(s.as_str())
    }
}

impl Serialize for ProfileName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ProfileName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ProfileNameVisitor;

        impl<'de> Visitor<'de> for ProfileNameVisitor {
            type Value = ProfileName;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a profile name string")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(ProfileName::parse(v))
            }

            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                if let Some(known) = KnownProfile::from_str_case_insensitive(&v) {
                    Ok(ProfileName::Known(known))
                } else {
                    Ok(ProfileName::Custom(Cow::Owned(v)))
                }
            }
        }

        deserializer.deserialize_str(ProfileNameVisitor)
    }
}

/// Environment variable names checked in precedence order for profile resolution.
pub const PROFILE_ENV_VARS: &[&str] = &[
    "KEYHOG_PROFILE",
    "KEYHOG_PROFILE_NAME",
    "KEYHOG_ENV",
    "PROFILE",
];

/// Resolve the active profile name from environment variables without heap allocations for known names.
///
/// Checks [`PROFILE_ENV_VARS`] in order. Returns `None` if no relevant environment variable is set.
#[must_use]
pub fn resolve_profile_from_env() -> Option<ProfileName> {
    for &var_name in PROFILE_ENV_VARS {
        if let Some(profile) = resolve_profile_from_env_var(var_name) {
            return Some(profile);
        }
    }
    None
}

/// Resolve a profile name from a specific environment variable name.
///
/// Avoids heap allocations when the variable value corresponds to a known profile.
#[must_use]
pub fn resolve_profile_from_env_var(var_name: &str) -> Option<ProfileName> {
    let os_val = std::env::var_os(var_name)?;
    let val_str = os_val.to_str()?;
    let trimmed = val_str.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(resolve_profile_from_env_value(trimmed))
}

/// Resolve a profile name from a raw string value without heap allocations for known profile names.
#[must_use]
pub fn resolve_profile_from_env_value(val: &str) -> ProfileName {
    ProfileName::parse(val)
}

/// Look up a profile name in a borrowed slice without heap allocations for known names.
#[must_use]
pub fn lookup_profile_name<'a>(name: &'a str) -> Cow<'a, str> {
    if let Some(known) = KnownProfile::from_str_case_insensitive(name) {
        Cow::Borrowed(known.as_str())
    } else {
        Cow::Borrowed(name.trim())
    }
}

fn default_true() -> bool {
    true
}

fn default_sample_rate() -> f64 {
    1.0
}

fn default_max_events() -> usize {
    10_000
}

/// Profile configuration controlling execution mode, telemetry, and credentials.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfig {
    /// Profile identifier.
    #[serde(default)]
    pub name: ProfileName,
    /// Whether profiling and telemetry collection are enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Profiling detail level.
    #[serde(default)]
    pub detail: Detail,
    /// Remote collector endpoint URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Authentication bearer or session token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<SensitiveString>,
    /// API key for authenticated profile reporting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<SensitiveString>,
    /// Secret transport or signing key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_key: Option<SensitiveString>,
    /// Target environment tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// Event sampling rate from 0.0 to 1.0.
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f64,
    /// Maximum in-memory event buffer cap.
    #[serde(default = "default_max_events")]
    pub max_events: usize,
    /// Custom metadata tags.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub tags: HashMap<String, String>,
    /// Sensitive HTTP request headers.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, SensitiveString>,
}

impl ProfileConfig {
    /// Create a new profile configuration with default settings for the given profile name.
    #[must_use]
    pub fn new(name: impl Into<ProfileName>) -> Self {
        Self {
            name: name.into(),
            enabled: true,
            detail: Detail::Off,
            endpoint: None,
            auth_token: None,
            api_key: None,
            secret_key: None,
            environment: None,
            sample_rate: 1.0,
            max_events: 10_000,
            tags: HashMap::new(),
            headers: HashMap::new(),
        }
    }

    /// Parse profile configuration from a JSON string.
    ///
    /// Sensitive fields are wrapped in [`SensitiveString`]. On deserialization failure,
    /// any intermediate sensitive values are zeroized when dropped.
    pub fn parse_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Parse profile configuration from JSON bytes.
    ///
    /// Sensitive fields are wrapped in [`SensitiveString`]. On deserialization failure,
    /// any intermediate sensitive values are zeroized when dropped.
    pub fn parse_json_slice(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Zeroize all sensitive credentials and headers held in this configuration.
    pub fn zeroize(&mut self) {
        if let Some(token) = &mut self.auth_token {
            token.zeroize();
        }
        if let Some(key) = &mut self.api_key {
            key.zeroize();
        }
        if let Some(secret) = &mut self.secret_key {
            secret.zeroize();
        }
        for value in self.headers.values_mut() {
            value.zeroize();
        }
    }
}

impl Default for ProfileConfig {
    fn default() -> Self {
        Self::new(ProfileName::default())
    }
}

impl Zeroize for ProfileConfig {
    fn zeroize(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ProfileConfig {}
