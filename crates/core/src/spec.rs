//! Detector specification: TOML-based pattern definitions with regex, keywords,
//! verification endpoints, and companion patterns.

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
}

/// A regex pattern with optional capture group and description.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternSpec {
    /// Regular expression string (Rust flavor).
    pub regex: String,
    /// Optional context description.
    pub description: Option<String>,
    /// Optional capture group index containing the secret.
    pub group: Option<usize>,
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
    /// the resolved host of the (interpolated) URL — and of every step's URL —
    /// MUST equal one of these entries (or be a subdomain of one). When empty,
    /// the verifier falls back to a hardcoded service allowlist if the
    /// `service` field maps to a known provider; otherwise the verifier
    /// REFUSES to send the request. This blocks malicious detector TOMLs
    /// that set `url = "{{match}}"` (or interpolate an attacker-controlled
    /// companion) from exfiltrating credentials. See kimi-wave1 audit
    /// finding 4.1 + wave3 §1.
    #[serde(default)]
    pub allowed_domains: Vec<String>,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Info,
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
            Severity::Low => Severity::Info,
            Severity::Info => Severity::Info,
        }
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

#[cfg(test)]
mod tests {
    use super::Severity;

    #[test]
    fn severity_downgrade_walks_one_step() {
        assert_eq!(Severity::Critical.downgrade_one(), Severity::High);
        assert_eq!(Severity::High.downgrade_one(), Severity::Medium);
        assert_eq!(Severity::Medium.downgrade_one(), Severity::Low);
        assert_eq!(Severity::Low.downgrade_one(), Severity::Info);
    }

    #[test]
    fn severity_downgrade_floors_at_info() {
        assert_eq!(Severity::Info.downgrade_one(), Severity::Info);
    }

    #[test]
    fn severity_downgrade_is_monotonic() {
        // Repeated downgrade must not loop or skip — every step must be ≤ previous.
        let mut s = Severity::Critical;
        for _ in 0..10 {
            let next = s.downgrade_one();
            assert!(next <= s);
            s = next;
        }
        assert_eq!(s, Severity::Info);
    }
}
