//! Detector live-verification, OOB callback, auth, script engine, success policy, and severity specs.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::{DetectorSpec, MetadataSpec};

/// Live verification configuration for a detector.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Gated behind the runtime `--verify-oob` flag - never default. When a
    /// detector sets `oob`, verification requires an active OOB session and
    /// fails closed if the session is unavailable, rather than sending a
    /// malformed HTTP-only probe with empty interactsh substitutions.
    pub oob: Option<OobSpec>,
}

/// Out-of-band callback verification configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Verification policy (TOML wire values shown; serde is `snake_case`):
    /// - `oob_and_http` (default): both HTTP success criteria *and* OOB
    ///   callback must hold. This is the strict mode for webhook-style
    ///   detectors where 200 OK is necessary but not sufficient.
    /// - `oob_only`: ignore HTTP success, trust the OOB callback. For
    ///   detectors where the API has no useful HTTP response shape but
    ///   provably triggers an outbound request (e.g., one-way push tokens).
    /// - `oob_optional`: HTTP success alone verifies; OOB just enriches
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
    /// The credential is live only when the HTTP success criteria pass AND the OOB callback is observed.
    OobAndHttp,
    /// The credential is live purely on an observed OOB callback; the HTTP response is ignored.
    OobOnly,
    /// The HTTP success criteria decide the verdict; an observed OOB callback is added as extra evidence.
    OobOptional,
}

/// A single step in a multi-step verification flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepSpec {
    /// Step name referenced by later steps and by extracted-metadata keys.
    pub name: String,
    /// HTTP method used for this step's request.
    pub method: HttpMethod,
    /// Request URL template, interpolated with credential and prior-step values.
    pub url: String,
    /// Authentication scheme applied to this step's request.
    pub auth: AuthSpec,
    #[serde(default)]
    /// Extra request headers, each interpolated like the URL.
    pub headers: Vec<HeaderSpec>,
    /// Optional request body template.
    pub body: Option<String>,
    /// Criteria that decide whether this step succeeded.
    pub success: SuccessSpec,
    #[serde(default)]
    /// Values pulled out of this step's response for later steps and the finding.
    pub extract: Vec<MetadataSpec>,
}

/// Custom HTTP header specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderSpec {
    /// Header field name sent verbatim.
    pub name: String,
    /// Header value template, interpolated before the request is sent.
    pub value: String,
}

/// Authentication scheme for verification requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthSpec {
    /// Unauthenticated request.
    None {},
    /// `Authorization: Bearer <value>`.
    Bearer {
        /// Companion or credential field supplying the bearer value.
        field: String,
    },
    /// HTTP basic authentication.
    Basic {
        /// Username template.
        username: String,
        /// Password template.
        password: String,
    },
    /// Credential carried in a custom header.
    Header {
        /// Header field name.
        name: String,
        /// Header value template.
        template: String,
    },
    /// Credential carried in a query-string parameter.
    Query {
        /// Query parameter name.
        param: String,
        /// Companion or credential field supplying the parameter value.
        field: String,
    },
    #[serde(rename = "aws_v4")]
    /// AWS Signature Version 4 request signing.
    AwsV4 {
        /// Field supplying the access key id.
        access_key: String,
        /// Field supplying the secret access key.
        secret_key: String,
        /// AWS region the request is signed for.
        region: String,
        /// AWS service name the request is signed for.
        service: String,
        /// Optional field supplying a session token.
        session_token: Option<String>,
    },
    /// Credential prepared by an external interpreter script.
    Script {
        /// Interpreter that runs `code`.
        engine: ScriptEngine,
        /// Script source executed to produce the request credential.
        code: String,
    },
}

/// Script interpreter names accepted by the detector TOML schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptEngine {
    /// CPython 3 (`python3`).
    Python3,
    /// Ambient CPython (`python`).
    Python,
    /// Node.js (`node`).
    Node,
    /// Any other engine name; parsed but refused for verification.
    Other(String),
}

impl ScriptEngine {
    /// Engine names a detector may use for live verification.
    pub const ALLOWED_FOR_VERIFY: &'static [&'static str] = &["python3", "python", "node"];

    /// Wire name of this engine, as written in detector TOML.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Python3 => "python3",
            Self::Python => "python",
            Self::Node => "node",
            Self::Other(engine) => engine,
        }
    }

    /// True when this engine is allowed to run during live verification.
    pub fn is_allowed_for_verify(&self) -> bool {
        matches!(self, Self::Python3 | Self::Python | Self::Node)
    }
}

impl From<String> for ScriptEngine {
    fn from(engine: String) -> Self {
        match engine.as_str() {
            "python3" => Self::Python3,
            "python" => Self::Python,
            "node" => Self::Node,
            _ => Self::Other(engine),
        }
    }
}

impl From<&str> for ScriptEngine {
    fn from(engine: &str) -> Self {
        Self::from(engine.to_owned())
    }
}

impl fmt::Display for ScriptEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ScriptEngine {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ScriptEngine {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(String::deserialize(deserializer)?.into())
    }
}

/// How a verifier response establishes a successful credential check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuccessPolicy {
    /// Stable response-body evidence must match.
    BodyPositive,
    /// The accepted status is necessary, then the generic provider-error body
    /// backstop must still reject populated error signals.
    StatusWithErrorBackstop,
    /// The provider protocol makes the accepted status authoritative even when
    /// the response body is empty or unstable.
    StatusAuthoritative,
}

/// Criteria for a successful verification response.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SuccessSpec {
    #[serde(default)]
    /// Required HTTP status code.
    pub status: Option<u16>,
    #[serde(default)]
    /// Reject if this status code is returned.
    pub status_not: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Explicit response-success policy. Shipped detector contracts must
    /// classify this; `None` exists only for backwards-compatible decoding and
    /// is rejected by detector quality validation.
    pub policy: Option<SuccessPolicy>,
    #[serde(default)]
    /// Response body must contain this substring.
    pub body_contains: Option<String>,
    #[serde(default)]
    /// Response body must NOT contain this substring.
    pub body_not_contains: Option<String>,
    #[serde(default)]
    /// `$`-rooted response selector to check in the JSON response body.
    pub json_path: Option<String>,
    #[serde(default)]
    /// Expected value at \`json_path\`.
    pub equals: Option<String>,
}

/// Migrate unambiguous schema-v1 status-only success contracts to the
/// conservative explicit policy.
///
/// Returns the number of contracts migrated so the loader can surface legacy
/// normalization. Body-constrained, no-status, and already-classified contracts
/// remain untouched and will pass or fail normal validation without guessing.
pub(crate) fn migrate_legacy_success_policies(detector: &mut DetectorSpec) -> usize {
    let Some(verify) = detector.verify.as_mut() else {
        return 0;
    };

    let mut migrated = verify
        .success
        .as_mut()
        .is_some_and(migrate_legacy_success_policy) as usize;
    for step in &mut verify.steps {
        migrated += migrate_legacy_success_policy(&mut step.success) as usize;
    }
    migrated
}

fn migrate_legacy_success_policy(success: &mut SuccessSpec) -> bool {
    let is_unambiguous_status_only = success.policy.is_none()
        && success.status.is_some()
        && success.body_contains.is_none()
        && success.body_not_contains.is_none()
        && success.json_path.is_none()
        && success.equals.is_none();
    if !is_unambiguous_status_only {
        return false;
    }

    success.policy = Some(SuccessPolicy::StatusWithErrorBackstop);
    true
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    #[default]
    /// Informational only; not treated as a credential exposure.
    Info,
    /// Safe to ship to a client; an attacker gains nothing server-side.
    ClientSafe,
    /// Limited blast radius.
    Low,
    /// Meaningful blast radius.
    Medium,
    /// Serious blast radius.
    High,
    /// Full compromise of the referenced account or service.
    Critical,
}

/// Canonical `kebab-case` severity wire forms in `ORDERED` order, the set an
/// unknown-token deserialize error advertises. DERIVED (const-evaluated) from the
/// single [`Severity::ORDERED`] + [`Severity::as_str`] table so it can never drift
/// from what the enum actually renders and accepts: a variant added to `ORDERED`
/// appears here, and in the deserialize accept-list and the unknown-variant
/// diagnostic, automatically, with no second hand-maintained string list. Lists
/// only the canonical spellings and deliberately omits the private `client_safe`
/// back-compat alias (still *accepted* on input by the visitor below, never
/// advertised).
const SEVERITY_CANONICAL_WIRE_FORMS: [&str; Severity::ORDERED.len()] = {
    let mut out = [""; Severity::ORDERED.len()];
    let mut i = 0;
    while i < Severity::ORDERED.len() {
        out[i] = Severity::ORDERED[i].as_str();
        i += 1;
    }
    out
};

// Hand-written `Deserialize` (Serialize stays derived; `rename_all` makes it
// re-emit the canonical kebab form). Two reasons the derive is not enough:
//   * a non-string input (number/bool/null) must fail with an `invalid type`
//     error, the categorically-correct diagnostic, not the derive's
//     variant-identifier path; and
//   * an unknown token must advertise ONLY the canonical kebab forms while the
//     visitor still accepts the `client_safe` snake alias on input.
// Match is exact: case-sensitive and non-trimming (` critical `, `Critical`,
// `CLIENT-SAFE` all fail closed). No binary/non-self-describing serde path
// exists for `Severity` (every load is `serde_json`/`toml`, both self-describing
// with string values), so `deserialize_str` is safe here.
impl<'de> serde::Deserialize<'de> for Severity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SeverityVisitor;

        impl serde::de::Visitor<'_> for SeverityVisitor {
            type Value = Severity;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(
                    "a severity string (one of info, client-safe, low, medium, high, critical)",
                )
            }

            fn visit_str<E>(self, value: &str) -> Result<Severity, E>
            where
                E: serde::de::Error,
            {
                // Private back-compat alias, deliberately NOT a canonical wire
                // form (kept out of `as_str`/the advertised set).
                if value == "client_safe" {
                    return Ok(Severity::ClientSafe);
                }
                // Canonical match is EXACT (case-sensitive, non-trimming): compare
                // the input against each variant's single-source-of-truth
                // `as_str`, so `Critical`/` critical `/`CLIENT-SAFE`/`` all fall
                // through to the fail-closed unknown-variant path below.
                Severity::ORDERED
                    .iter()
                    .find(|variant| variant.as_str() == value)
                    .copied()
                    .ok_or_else(|| E::unknown_variant(value, &SEVERITY_CANONICAL_WIRE_FORMS))
            }
        }

        deserializer.deserialize_str(SeverityVisitor)
    }
}

impl Severity {
    pub(crate) const FILTER_EXPECTED_LABELS: &'static str =
        "info|client-safe|low|medium|high|critical";
    pub(crate) const ORDERED: [Severity; 6] = [
        Severity::Info,
        Severity::ClientSafe,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

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
    ///
    /// Public so downstream crates (the CLI completion/severity summary,
    /// stream previews) render severity text from this one table instead of
    /// keeping their own `match` copies that can drift.
    pub const fn as_str(&self) -> &'static str {
        // THE single source of truth for every severity wire form. `const` so the
        // canonical-wire-form set, the deserialize accept-list, and the filter
        // parser all DERIVE from this one table at compile time instead of
        // re-listing the six (variant, string) pairs and risking drift.
        match self {
            Severity::Info => "info",
            Severity::ClientSafe => "client-safe",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub(crate) fn from_filter_label(label: &str) -> Option<Self> {
        // Filter labels are lenient (trim + lowercase), unlike the exact
        // deserializer path above, but both resolve against the SAME single
        // `as_str` table so a new/renamed wire form is honoured everywhere at
        // once. `client_safe` snake alias is accepted here too.
        let normalized = label.trim().to_ascii_lowercase();
        if normalized == "client_safe" {
            return Some(Severity::ClientSafe);
        }
        Severity::ORDERED
            .iter()
            .find(|variant| variant.as_str() == normalized)
            .copied()
    }

    pub(crate) fn rank(self) -> usize {
        match Self::ORDERED
            .iter()
            .position(|candidate| *candidate == self)
        {
            Some(rank) => rank,
            None => Self::ORDERED.len() - 1, // LAW10: fail-closed/security: impossible enum/table drift clamps to highest severity so severity_lte cannot over-suppress.
        }
    }

    pub(crate) fn label_for_rank(rank: usize) -> &'static str {
        match Self::ORDERED.get(rank) {
            Some(severity) => severity.as_str(),
            None => Severity::Critical.as_str(), // LAW10: fail-closed/security: invalid rank maps to highest severity label so severity_lte cannot over-suppress.
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// HTTP method for verification requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpMethod {
    #[serde(rename = "GET")]
    /// HTTP `GET`.
    Get,
    #[serde(rename = "POST")]
    /// HTTP `POST`.
    Post,
    #[serde(rename = "PUT")]
    /// HTTP `PUT`.
    Put,
    #[serde(rename = "DELETE")]
    /// HTTP `DELETE`.
    Delete,
    #[serde(rename = "PATCH")]
    /// HTTP `PATCH`.
    Patch,
    #[serde(rename = "HEAD")]
    /// HTTP `HEAD`.
    Head,
}

