//! Detector specification: TOML-based pattern definitions with regex, keywords,
//! verification endpoints, and companion patterns.

// Debt bucket: 55 public items, each landed before the crate floor raised
// `missing_docs` to `warn`. Each is part of the public TOML schema and would
// benefit from a doc line; remove this allow once they all carry one.
#![allow(missing_docs)]

mod load;
mod validate;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use load::{
    load_detector_cache, load_detectors, load_detectors_from_str, load_detectors_with_gate,
    save_detector_cache,
};
pub use validate::{validate_detector, QualityIssue};

/// Metadata field specification for verification results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataSpec {
    /// Field name in the finding metadata map.
    pub name: String,
    /// GJSON path to extract from the verification response body.
    pub json_path: String,
}

/// A complete detector definition loaded from a TOML file.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DetectorSpec {
    /// Unique stable identifier (e.g. \`aws-access-key\`).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Target service (e.g. \`aws\`, \`stripe\`).
    pub service: String,
    /// Default severity for findings.
    pub severity: Severity,
    /// List of regex patterns to match.
    pub patterns: Vec<PatternSpec>,
    /// Secondary patterns required to confirm a match.
    #[serde(default)]
    pub companions: Vec<CompanionSpec>,
    /// Live verification configuration.
    pub verify: Option<VerifySpec>,
    /// High-performance pre-filtering keywords.
    #[serde(default)]
    pub keywords: Vec<String>,
    /// Self-declared per-detector confidence floor, in `[0.0, 1.0]`.
    ///
    /// When set, findings from THIS detector use this floor instead of the
    /// global `--min-confidence` / `[scan] min_confidence`. A detector with a
    /// distinctive vendor prefix (e.g. sourcegraph `sgp_<40hex>`, cursor
    /// `key_<64hex>`) is high-confidence by virtue of the prefix even when the
    /// body is low-entropy hex that the generic confidence model scores below
    /// the global floor; the detector author declares that here so the
    /// detector ships working out of the box. Costs nothing at scan time —
    /// it is a single O(1) map lookup at the post-scan floor gate, on an
    /// already-compiled corpus. An operator `.keyhog.toml`
    /// `[detector.<id>] min_confidence` still overrides this self-declared
    /// default. `None` (the default) means "use the global floor".
    #[serde(default)]
    pub min_confidence: Option<f64>,
}

/// A regex pattern with optional capture group and description.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PatternSpec {
    /// Regular expression string (Rust flavor).
    pub regex: String,
    /// Optional context description.
    pub description: Option<String>,
    /// Optional capture group index containing the secret.
    pub group: Option<usize>,
    /// When true, a match against THIS pattern downgrades the
    /// finding to `Severity::ClientSafe` (regardless of the detector's
    /// nominal severity). Used by services that intentionally ship
    /// public-facing keys in client bundles:
    ///
    ///   - Sentry DSN (the `https://<key>@` URL is meant for the browser)
    ///   - Stripe `pk_live_` / `pk_test_` (publishable, sk_ is secret)
    ///   - Mapbox `pk.` (public, `sk.` is secret)
    ///   - Firebase Web API key, Google Maps browser key
    ///   - PostHog / Mixpanel / Algolia search / Datadog browser RUM
    ///
    /// Per-pattern (not per-detector) so detectors that fire on both
    /// the public *and* the secret prefix can tag only the public one.
    ///
    /// Case sensitivity: keyhog compiles every regex `case_insensitive(true)`,
    /// so to make a single pattern case-SENSITIVE (AWS `AKIA` is uppercase,
    /// GCP/Snowflake ids are lowercase) prefix its regex with the inline flag
    /// `(?-i)` in the TOML - no schema field needed.
    #[serde(default)]
    pub client_safe: bool,
}

/// Secondary pattern used to confirm a primary match or provide extra context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanionSpec {
    /// Field name used in verification templates (e.g. \`{{companion.secret_key}}\`).
    pub name: String,
    /// Regex to find the companion value nearby.
    pub regex: String,
    /// Maximum line distance from the primary match.
    pub within_lines: usize,
    /// Whether this companion must be found to report the finding.
    #[serde(default)]
    pub required: bool,
}

/// Live verification configuration for a detector.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerifySpec {
    /// Target service identifier (defaults to detector's service if omitted).
    #[serde(default)]
    pub service: String,
    /// HTTP method (default: GET).
    pub method: Option<HttpMethod>,
    /// Endpoint URL with optional \`{{match}}\` or \`{{companion.<name>}}\` placeholders.
    pub url: Option<String>,
    /// Authentication scheme.
    pub auth: Option<AuthSpec>,
    /// Custom HTTP headers.
    #[serde(default)]
    pub headers: Vec<HeaderSpec>,
    /// Optional request body template.
    pub body: Option<String>,
    /// Criteria for a successful verification.
    pub success: Option<SuccessSpec>,
    /// Metadata to extract from the response.
    #[serde(default)]
    pub metadata: Vec<MetadataSpec>,
    /// Optional request timeout override.
    pub timeout_ms: Option<u64>,
    /// Multi-step verification flow.
    #[serde(default)]
    pub steps: Vec<StepSpec>,
    /// Domain allowlist for the verify URL after interpolation. If non-empty,
    /// the resolved host of the (interpolated) URL - and of every step's URL -
    /// MUST equal one of these entries (or be a subdomain of one). When empty,
    /// the verifier falls back to a hardcoded service allowlist if the
    /// `service` field maps to a known provider; otherwise the verifier
    /// REFUSES to send the request. This blocks malicious detector TOMLs
    /// that set `url = "{{match}}"` (or interpolate an attacker-controlled
    /// companion) from exfiltrating credentials. See kimi-wave1 audit
    /// finding 4.1 + wave3 §1.
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// Optional out-of-band verification probe. When set, the verifier mints a
    /// per-finding correlation URL via the configured interactsh server,
    /// substitutes `{{interactsh}}` (and `{{interactsh.host}}` /
    /// `{{interactsh.url}}`) into the request template, and waits for the
    /// service to call back. OOB verification proves a leaked credential is
    /// **exfil-capable**, not just live: a webhook URL that returns 200 OK to
    /// every probe still has to actually fetch our collector to confirm it
    /// will deliver attacker-controlled traffic.
    ///
    /// Gated behind the runtime `--verify-oob` flag - never default. When the
    /// flag is off, `oob` is ignored and verification falls back to the
    /// HTTP success criteria alone.
    pub oob: Option<OobSpec>,
}

/// Out-of-band callback verification configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OobSpec {
    /// Callback protocol the verifier waits for. The service may also touch
    /// other protocols on the same correlation id; only the listed ones count
    /// toward `Verified`.
    pub protocol: OobProtocol,
    /// How long to wait for the callback after the HTTP request returns.
    /// Defaults to 30 seconds when omitted; capped at the engine's
    /// `oob_timeout_max` to bound scan time.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    /// Verification policy:
    /// - `OobAndHttp` (default): both HTTP success criteria *and* OOB
    ///   callback must hold. This is the strict mode for webhook-style
    ///   detectors where 200 OK is necessary but not sufficient.
    /// - `OobOnly`: ignore HTTP success, trust the OOB callback. For
    ///   detectors where the API has no useful HTTP response shape but
    ///   provably triggers an outbound request (e.g., one-way push tokens).
    /// - `OobOptional`: HTTP success alone verifies; OOB just enriches
    ///   metadata with `oob_observed=true|false` for the report.
    #[serde(default)]
    pub policy: OobPolicy,
}

/// Out-of-band callback protocol expected from a successful exfil.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OobProtocol {
    /// Any DNS resolution against `{{interactsh}}.host`. Cheapest signal -
    /// many services resolve a webhook URL even before fetching it.
    Dns,
    /// HTTP or HTTPS request to the interactsh URL. The strongest signal;
    /// proves the service made an outbound HTTP request with the credential.
    Http,
    /// SMTP delivery attempt to `<random>@{{interactsh.host}}`. For mail
    /// detectors (Mailgun, SendGrid, …) where exfil = sending mail.
    Smtp,
    /// Any of the above. Use sparingly - a chatty CDN doing DNS prefetch
    /// can cause false positives.
    Any,
}

/// How OOB observation combines with HTTP success criteria.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OobPolicy {
    #[default]
    OobAndHttp,
    OobOnly,
    OobOptional,
}

/// A single step in a multi-step verification flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepSpec {
    pub name: String,
    pub method: HttpMethod,
    pub url: String,
    pub auth: AuthSpec,
    #[serde(default)]
    pub headers: Vec<HeaderSpec>,
    pub body: Option<String>,
    pub success: SuccessSpec,
    #[serde(default)]
    pub extract: Vec<MetadataSpec>,
}

/// Custom HTTP header specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderSpec {
    pub name: String,
    pub value: String,
}

/// Authentication scheme for verification requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthSpec {
    None,
    Bearer {
        field: String,
    },
    Basic {
        username: String,
        password: String,
    },
    Header {
        name: String,
        template: String,
    },
    Query {
        param: String,
        field: String,
    },
    #[serde(rename = "aws_v4")]
    AwsV4 {
        access_key: String,
        secret_key: String,
        region: String,
        service: String,
        session_token: Option<String>,
    },
    Script {
        engine: String,
        code: String,
    },
}

impl AuthSpec {
    pub fn service_name(&self) -> Option<&str> {
        match self {
            AuthSpec::AwsV4 { service, .. } => Some(service),
            _ => None,
        }
    }
}

/// Criteria for a successful verification response.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SuccessSpec {
    #[serde(default)]
    /// Required HTTP status code.
    pub status: Option<u16>,
    #[serde(default)]
    /// Reject if this status code is returned.
    pub status_not: Option<u16>,
    #[serde(default)]
    /// Response body must contain this substring.
    pub body_contains: Option<String>,
    #[serde(default)]
    /// Response body must NOT contain this substring.
    pub body_not_contains: Option<String>,
    #[serde(default)]
    /// GJSON path to check in response body.
    pub json_path: Option<String>,
    #[serde(default)]
    /// Expected value at \`json_path\`.
    pub equals: Option<String>,
}

/// Severity level for a finding.
///
/// `ClientSafe` is the bug-bounty tier for keys that are public by
/// design and shipped in client bundles: Sentry DSNs, Stripe `pk_*`
/// publishable keys, Mapbox `pk.` public tokens, PostHog project keys,
/// Firebase Web API keys, Google Maps browser keys, Algolia search
/// keys, Datadog browser RUM tokens, Mixpanel project tokens. The
/// detector still fires (a token grep is a token grep) but the
/// finding is rendered below `Low` and gated by `--hide-client-safe`
/// so a hunter running `keyhog scan --hide-client-safe target/` only
/// sees credentials that an attacker could actually exfiltrate
/// server-side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    #[default]
    Info,
    #[serde(alias = "client_safe")]
    ClientSafe,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn to_severity(&self) -> Self {
        *self
    }

    /// Step the severity down one tier (Critical → High, High → Medium, …).
    /// `Info` stays at `Info` (no lower bucket).
    ///
    /// Used by diff-aware scoring: a credential that only appears in non-HEAD
    /// git history is still a leak (commit history is public if the repo is)
    /// but is meaningfully less urgent than a credential live in HEAD that an
    /// attacker can grep right now. One tier of downgrade communicates that
    /// without hiding the finding entirely.
    pub fn downgrade_one(self) -> Self {
        match self {
            Severity::Critical => Severity::High,
            Severity::High => Severity::Medium,
            Severity::Medium => Severity::Low,
            Severity::Low => Severity::ClientSafe,
            Severity::ClientSafe => Severity::Info,
            Severity::Info => Severity::Info,
        }
    }

    /// Canonical lowercase string for this severity, matching the serde
    /// `kebab-case` wire form (`client-safe`, not `clientsafe`). This is the
    /// single source of truth for rendering a severity as text; reporters and
    /// any other surface should go through `Display`/`as_str` rather than
    /// reaching for `format!("{:?}")`, which diverges for `ClientSafe`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::ClientSafe => "client-safe",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// HTTP method for verification requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HttpMethod {
    #[serde(rename = "GET")]
    Get,
    #[serde(rename = "POST")]
    Post,
    #[serde(rename = "PUT")]
    Put,
    #[serde(rename = "DELETE")]
    Delete,
    #[serde(rename = "PATCH")]
    Patch,
    #[serde(rename = "HEAD")]
    Head,
}

/// Wrapping struct for a detector TOML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorFile {
    pub detector: DetectorSpec,
}

/// Errors returned while loading or validating detector specifications.
#[derive(Debug, Error)]
#[allow(clippy::result_large_err)] // SpecError variants include 128-byte toml::de::Error; boxing would be a breaking API change.
pub enum SpecError {
    #[error(
        "failed to read detector file {path}: {source}. Fix: check the detector path exists and that the file is readable TOML"
    )]
    ReadFile {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid TOML in detector {path}: {source}. Fix: repair the TOML syntax in the detector file")]
    InvalidToml {
        path: std::path::PathBuf,
        source: toml::de::Error,
    },
}
