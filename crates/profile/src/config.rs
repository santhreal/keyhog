//! Profile configuration models and zero-allocation profile lookup.
//!
//! Provides [`ProfileConfig`] for configuring execution profiles and telemetry,
//! and zero-allocation lookup routines for known profile names.

use std::borrow::{Borrow, Cow};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Deref;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::Detail;

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
///
/// Note: Known profile names (such as `"ci"`, `"default"`, `"release"`) are normalized to
/// their canonical lowercase representation during parsing, whereas custom profile names
/// preserve their original case.
#[derive(Clone, Debug)]
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
    ///
    /// Standard profile names are matched case-insensitively and canonicalized to lowercase,
    /// while custom profile names preserve case.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        let trimmed = s.trim();
        if let Some(known) = KnownProfile::from_str_case_insensitive(trimmed) {
            Self::Known(known)
        } else {
            Self::Custom(Cow::Owned(trimmed.to_owned()))
        }
    }

    /// Construct a profile name from a static string slice with zero heap allocations.
    #[must_use]
    pub fn from_static(s: &'static str) -> Self {
        let trimmed = s.trim();
        if let Some(known) = KnownProfile::from_str_case_insensitive(trimmed) {
            Self::Known(known)
        } else {
            Self::Custom(Cow::Borrowed(trimmed))
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

impl PartialEq for ProfileName {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for ProfileName {}

impl PartialOrd for ProfileName {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ProfileName {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl Hash for ProfileName {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
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
        let trimmed = s.trim();
        if let Some(known) = KnownProfile::from_str_case_insensitive(trimmed) {
            Self::Known(known)
        } else if trimmed.len() == s.len() {
            Self::Custom(Cow::Owned(s))
        } else {
            Self::Custom(Cow::Owned(trimmed.to_owned()))
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
                Ok(ProfileName::from(v))
            }
        }

        deserializer.deserialize_str(ProfileNameVisitor)
    }
}

/// Environment variable names checked in precedence order for profile resolution.
pub const PROFILE_ENV_VARS: &[&str] = &["KEYHOG_PROFILE", "KEYHOG_PROFILE_NAME", "KEYHOG_ENV"];

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
pub fn lookup_profile_name(name: &str) -> &str {
    if let Some(known) = KnownProfile::from_str_case_insensitive(name) {
        known.as_str()
    } else {
        name.trim()
    }
}

const DEFAULT_ENABLED: bool = true;
const DEFAULT_SAMPLE_RATE: f64 = 1.0;
const DEFAULT_MAX_EVENTS: usize = 10_000;

const fn default_enabled() -> bool {
    DEFAULT_ENABLED
}

const fn default_sample_rate() -> f64 {
    DEFAULT_SAMPLE_RATE
}

const fn default_max_events() -> usize {
    DEFAULT_MAX_EVENTS
}

/// Profile configuration controlling execution mode, telemetry, and credentials.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfig {
    /// Profile identifier.
    #[serde(default)]
    pub name: ProfileName,
    /// Whether profiling and telemetry collection are enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Profiling detail level.
    #[serde(default)]
    pub detail: Detail,
    /// Remote collector endpoint URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Authentication bearer or session token (never serialized).
    #[serde(default, skip_serializing)]
    pub auth_token: Option<Zeroizing<String>>,
    /// API key for authenticated profile reporting (never serialized).
    #[serde(default, skip_serializing)]
    pub api_key: Option<Zeroizing<String>>,
    /// Secret transport or signing key (never serialized).
    #[serde(default, skip_serializing)]
    pub secret_key: Option<Zeroizing<String>>,
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
    /// Sensitive HTTP request headers (never serialized).
    #[serde(default, skip_serializing)]
    pub headers: HashMap<String, Zeroizing<String>>,
}

impl ProfileConfig {
    /// Create a new profile configuration with default settings for the given profile name.
    #[must_use]
    pub fn new(name: impl Into<ProfileName>) -> Self {
        Self {
            name: name.into(),
            enabled: DEFAULT_ENABLED,
            detail: Detail::Off,
            endpoint: None,
            auth_token: None,
            api_key: None,
            secret_key: None,
            environment: None,
            sample_rate: DEFAULT_SAMPLE_RATE,
            max_events: DEFAULT_MAX_EVENTS,
            tags: HashMap::new(),
            headers: HashMap::new(),
        }
    }

    /// Parse profile configuration from a JSON string.
    pub fn parse_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Parse profile configuration from JSON bytes.
    pub fn parse_json_slice(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Zeroize all sensitive credentials and headers held in this configuration.
    pub fn zeroize(&mut self) {
        if let Some(mut token) = self.auth_token.take() {
            token.zeroize();
        }
        if let Some(mut key) = self.api_key.take() {
            key.zeroize();
        }
        if let Some(mut secret) = self.secret_key.take() {
            secret.zeroize();
        }
        for (_, mut value) in self.headers.drain() {
            value.zeroize();
        }
    }
}

impl fmt::Debug for ProfileConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProfileConfig")
            .field("name", &self.name)
            .field("enabled", &self.enabled)
            .field("detail", &self.detail)
            .field("endpoint", &self.endpoint)
            .field(
                "auth_token",
                &self.auth_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .field(
                "secret_key",
                &self.secret_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("environment", &self.environment)
            .field("sample_rate", &self.sample_rate)
            .field("max_events", &self.max_events)
            .field("tags", &self.tags)
            .field(
                "headers",
                &if self.headers.is_empty() {
                    "{}"
                } else {
                    "{[REDACTED]}"
                },
            )
            .finish()
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
impl Drop for ProfileConfig {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ProfileConfig {}
