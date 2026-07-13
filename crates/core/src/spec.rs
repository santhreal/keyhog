//! Detector specification: TOML-based pattern definitions with regex, keywords,
//! verification endpoints, and companion patterns.

// Debt bucket: 55 public items, each landed before the crate floor raised
// `missing_docs` to `warn`. Each is part of the public TOML schema and would
// benefit from a doc line; remove this allow once they all carry one.
#![allow(missing_docs)]

pub(crate) mod load;
mod regex_separator;
mod validate;

use std::fmt;

use serde::{Deserialize, Serialize};

pub use load::{load_detectors, read_detector_toml_file, SpecError, DETECTOR_TOML_FILE_BYTES};
pub use regex_separator::{canonicalize_keyword_separators, CANONICAL_SEPARATOR};
pub use validate::{validate_detector, QualityIssue};

/// serde adapter for every detector `regex` field: deserialize the string, then
/// collapse its inter-keyword separator classes to the single canonical form
/// (see [`regex_separator`]). Applied at the spec boundary so the canonical
/// regex is the ONLY form any downstream consumer, the compiler, AC-literal
/// extraction, Hyperscan, literal prefixes, the spec hash, the bench, ever
/// sees. A real secret is therefore never missed because a leaked file used a
/// tab, a double space, or a hyphen where the detector author allowed only one
/// underscore.
fn deserialize_canonical_regex<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    Ok(canonicalize_keyword_separators(&raw).into_owned())
}

/// Metadata field specification for verification results.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataSpec {
    /// Field name in the finding metadata map.
    pub name: String,
    /// GJSON path to extract from the verification response body.
    pub json_path: String,
}

/// A complete detector definition loaded from a TOML file.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DetectorSpec {
    /// Unique stable identifier (e.g. \`aws-access-key\`).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Target service (e.g. \`aws\`, \`stripe\`).
    pub service: String,
    /// Default severity for findings.
    pub severity: Severity,
    /// What scan phase produces this detector's findings, and thus what the
    /// loader requires of it. Defaults to [`DetectorKind::Regex`]. A `regex`
    /// detector carries >=1 regex pattern and fires in phase 1. A
    /// `phase2-generic` detector is a shapeless-secret bridge: bare passwords
    /// and high-entropy blobs fire in phase 2 from `keywords` plus
    /// `entropy_floor`. It may also declare structured regex envelopes while
    /// keeping both paths under one detector owner. Modeled here so those
    /// detectors are first-class TOML specs, one home for every knob, instead
    /// of engine constants scattered across `detector_ids.rs` and policy files.
    #[serde(default)]
    pub kind: DetectorKind,
    /// List of regex patterns to match. Defaults to empty so a
    /// `kind = "phase2-generic"` detector can omit it when it has no structured
    /// envelope; a `kind = "regex"` detector with no patterns is rejected by
    /// the quality gate (`validate_patterns_present`), so this default never
    /// silently ships a dead regex detector.
    #[serde(default)]
    pub patterns: Vec<PatternSpec>,
    /// Secondary patterns required to confirm a match.
    #[serde(default)]
    pub companions: Vec<CompanionSpec>,
    /// Live verification configuration.
    pub verify: Option<VerifySpec>,
    /// High-performance pre-filtering keywords.
    #[serde(default)]
    pub keywords: Vec<String>,
    /// Literal prefixes eligible for the optional `simdsieve` first-pass
    /// accelerator. Each prefix must be non-empty ASCII, unique in the loaded
    /// corpus, and an actual literal prefix of one of this detector's patterns.
    /// Empty means this detector does not participate in that accelerator.
    #[serde(default)]
    pub simdsieve_prefixes: Vec<String>,
    /// Self-declared per-detector confidence floor, in `[0.0, 1.0]`.
    ///
    /// When set, findings from THIS detector use this floor instead of the
    /// global `--min-confidence` / `[scan].min_confidence`. A detector with a
    /// distinctive vendor prefix (e.g. sourcegraph `sgp_<40hex>`, cursor
    /// `key_<64hex>`) is high-confidence by virtue of the prefix even when the
    /// body is low-entropy hex that the generic confidence model scores below
    /// the global floor; the detector author declares that here so the
    /// detector ships working out of the box. Costs nothing at scan time
    /// it is a single O(1) map lookup at the post-scan floor gate, on an
    /// already-compiled corpus. An operator `.keyhog.toml`
    /// `[detector.<id>] min_confidence` still overrides this self-declared
    /// default. `None` (the default) means "use the global floor".
    #[serde(default)]
    pub min_confidence: Option<f64>,
    /// Per-detector low-entropy suppression floor, owned HERE in the detector's
    /// own TOML, the single source of truth for the generic-detector entropy
    /// gate (there is no separate `rules/entropy-floors.toml`, no code table, no
    /// override). Length-bucketed: the FIRST bucket (in listed order) whose
    /// `max_len >= L` sets the floor for a candidate of length `L`; the last
    /// bucket omits `max_len` and is the catch-all. `max_len` must strictly
    /// increase. A generic-detector candidate whose Shannon entropy is BELOW the
    /// applicable floor is suppressed. Empty (the default) means the detector
    /// declares no floor and the generic default (`EntropyFloorTable::DEFAULT_FLOOR`)
    /// applies. Only the handful of `generic-*` detectors set this.
    #[serde(default)]
    pub entropy_floor: Vec<EntropyFloorBucket>,
    // ── PER-DETECTOR RECALL/PRECISION KNOBS (migration 2026-07-07) ────────────
    // ARCHITECTURE LAW: there is NO global/overall entropy or recall/precision
    // gate applied uniformly to every candidate. EVERY threshold that affects
    // whether a candidate survives is a PER-DETECTOR field, OWNED HERE in the
    // detector's own TOML spec, exactly like `min_confidence`/`entropy_floor`
    // above. Each is an `Option`/`Vec` that OVERRIDES a single named default
    // (the one remaining owner of the fallback value, `keyhog_scanner::entropy`
    // consts) only when the detector is silent. Reading two places to understand
    // one detector's behavior is banned (a detector's TOML is the whole story).
    /// Per-detector HIGH-entropy threshold (bits/byte), the keyword-independent
    /// bar. `None` → the single-owner default `HIGH_ENTROPY_THRESHOLD`.
    #[serde(default)]
    pub entropy_high: Option<f64>,
    /// Per-detector keyword-context (LOW) entropy threshold (bits/byte).
    /// `None` → the single-owner default `LOW_ENTROPY_THRESHOLD`.
    #[serde(default)]
    pub entropy_low: Option<f64>,
    /// Per-detector VERY-high entropy threshold for keyword-free/isolated tokens.
    /// `None` → the single-owner default `VERY_HIGH_ENTROPY_THRESHOLD`.
    #[serde(default)]
    pub entropy_very_high: Option<f64>,
    /// Per-detector mixed-alnum token entropy floor (bits/byte).
    /// `None` → the single-owner default `MIXED_ALNUM_TOKEN_THRESHOLD`.
    #[serde(default)]
    pub mixed_alnum_floor: Option<f64>,
    /// Per-detector BPE token-efficiency ceiling in UTF-8 bytes per
    /// `cl100k_base` token. Candidates above the ceiling are word-like and are
    /// suppressed after the cheaper entropy/shape gates. `None` preserves the
    /// compatible per-scan `entropy_bpe_max_bytes_per_token` fallback; `Some`
    /// makes this detector TOML the policy owner.
    #[serde(default)]
    pub bpe_max_bytes_per_token: Option<f64>,
    /// Whether the BPE token-efficiency precision gate applies to this
    /// detector. `None` inherits the enabled default; `Some(false)` disables
    /// tokenization for detector families such as human-chosen passwords where
    /// word-like values are legitimate. A disabled detector must not also set a
    /// BPE ceiling.
    #[serde(default)]
    pub bpe_enabled: Option<bool>,
    /// Per-detector minimum length for an anchor-free (keyword-free/isolated)
    /// candidate. `None` → the single-owner default `KEYWORD_FREE_MIN_LEN`.
    #[serde(default)]
    pub keyword_free_min_len: Option<usize>,
    /// Per-detector minimum candidate length (any candidate this detector emits).
    /// `None` → no detector-specific length floor beyond the path-wide default.
    #[serde(default)]
    pub min_len: Option<usize>,
    /// Per-detector maximum byte length for phase-2 generic assignment values.
    /// Values above this ceiling are rejected whole; they are never truncated
    /// into an apparently valid credential. Omission uses the typed 128-byte
    /// compiled fallback.
    #[serde(default)]
    pub max_len: Option<usize>,
    /// Per-detector path-exclusion regexes (betterleaks-style allowlist): a match
    /// whose FILE PATH matches any of these is suppressed. Owned per detector.
    #[serde(default)]
    pub allowlist_paths: Vec<String>,
    /// Per-detector value-exclusion regexes: a matched SECRET VALUE matching any
    /// of these is suppressed (per-detector test/example/placeholder demotion).
    #[serde(default)]
    pub allowlist_values: Vec<String>,
    /// Per-detector literal stopwords: a matched value equal to / containing any
    /// of these (case-insensitive) is suppressed. Owned per detector.
    #[serde(default)]
    pub stopwords: Vec<String>,
    /// Per-detector "structural password slot" classification, OWNED HERE per the
    /// architecture law above (was a hardcoded detector-id list in scanner
    /// code, so a detector's family lived outside its TOML).
    ///
    /// `true` marks a STRONG-anchor detector whose regex proves a syntactic
    /// credential SLOT (`scheme://user:<x>@host`, `IDENTIFIED BY '<x>'`,
    /// `--password <x>`, `Bearer <x>`) but captures a FREE-FORM value the way a
    /// real password is written. Such detectors apply the password-slot
    /// placeholder gate (drop a captured literal dictionary word like `password`
    /// / `secret`, or a low-letter-diversity mask like `xxxxxxxx`) that a
    /// service-anchored detector's structured capture never needs. A new
    /// structural-password-slot detector now declares this in its own TOML, no
    /// code edit (and the whole story lives in the detector file).
    #[serde(default)]
    pub structural_password_slot: bool,
    /// Per-detector "weak anchor" classification, OWNED HERE per the architecture
    /// law above (was a centralized id list in `rules/detector-classification.toml`
    /// `weak_anchor = [...]`, so a detector's family lived in a second file, the
    /// rules TOML (not its own)).
    ///
    /// `true` marks a SERVICE-anchored detector whose regex capture nonetheless
    /// structurally collides with a generic value (a bare hex/base64 run the
    /// vendor prefix does not tightly bound: `alchemy-api-key`, `carbon-black-api-key`,
    /// `flickr-api-key`, …), so scanner suppression keeps the Tier-B shape gates
    /// ENGAGED for it (`WeakAnchorBase::Always`) instead of trusting the anchor.
    /// Without this the collision-prone captures would bypass the generic
    /// shape/entropy floors and flood FP. The structural-password-slot family is
    /// deliberately NOT weak_anchor (its slot is syntactic, not a vendor prefix).
    /// A new weak-anchor detector now declares this in its own TOML, no code
    /// edit (and the whole story lives in the detector file).
    #[serde(default)]
    pub weak_anchor: bool,
    /// Per-detector "private-key block" classification, OWNED HERE per the
    /// architecture law above (was a centralized id list in
    /// `rules/detector-classification.toml` `private_key_block = [...]`).
    ///
    /// `true` marks a detector whose match SPAN is an enclosing private-key block
    /// (`private-key`, `ssh-private-key`, `github-app-private-key`), a multi-line
    /// PEM/OpenSSH body. Resolution (`resolution::suppress_matches_nested_in_private_key_blocks`)
    /// fully suppresses any lower-specificity child finding nested inside such a
    /// span (an entropy/base64 hit on a line INSIDE the key body is not a second
    /// secret). A new private-key-block detector now declares this in its own TOML
    ///: no code edit (and the whole story lives in the detector file).
    #[serde(default)]
    pub private_key_block: bool,
    /// Per-detector credential shape constraint (see [`CredentialShape`]), OWNED
    /// HERE per the architecture law (was `rules/detector-credential-shapes.toml`).
    /// `None` (the default) means the detector declares no shape constraint.
    #[serde(default)]
    pub credential_shape: Option<CredentialShape>,
    /// Inline self-test fixtures (`[[detector.tests]]`, Tier-B data): each entry
    /// carries a positive example the detector MUST fire on and/or a negative
    /// example it MUST NOT. Consumed by the contract/self-validate harness;
    /// ignored at scan time. Modeled here (rather than silently dropped) so the
    /// schema's `deny_unknown_fields` typo-guard covers the whole detector file.
    #[serde(default)]
    pub tests: Vec<DetectorTestSpec>,
}

/// Which scan phase produces a detector's findings (see [`DetectorSpec::kind`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DetectorKind {
    /// Phase-1 regex detector: carries >=1 regex pattern, has a distinctive
    /// anchor. The default and the vast majority of the corpus.
    #[default]
    Regex,
    /// Phase-2 generic bridge: fires on `keywords` + `entropy_floor`. It may
    /// additionally carry explicit regex patterns for strongly structured
    /// envelopes (for example a JSON `"secret"` field); those anchors compile
    /// through the same detector while phase-2 remains the shapeless fallback.
    Phase2Generic,
}

/// One length bucket of a detector's [`DetectorSpec::entropy_floor`]. Owned in the
/// detector's TOML (`entropy_floor = [{ max_len = 24, floor = 3.0 }, { floor = 3.5 }]`).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EntropyFloorBucket {
    /// Inclusive maximum candidate length this bucket applies to. Omit on the
    /// final catch-all bucket (applies to any longer candidate).
    #[serde(default)]
    pub max_len: Option<usize>,
    /// Shannon-entropy floor (bits/byte). A candidate scoring below this is
    /// suppressed by the low-entropy gate.
    pub floor: f64,
}

/// Per-detector credential SHAPE constraint (`[detector.credential_shape]`),
/// OWNED HERE per the architecture law (was a centralized
/// `rules/detector-credential-shapes.toml` `[[shape]]` list keyed by detector
/// id, a per-detector property in a second file). A candidate whose byte length
/// / prefix / post-prefix body length does not fit the declared shape is
/// suppressed by the scanner's shape gate (`CredentialShapeRule::allows`). Only a
/// couple of fixed-format vendor detectors declare it: `aws-access-key` is
/// exactly 20 bytes; `anthropic-api-key` is `sk-ant-api03-` + an 80..=120 body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CredentialShape {
    /// Exact total credential byte length, for a fixed-length format.
    #[serde(default)]
    pub exact_length: Option<usize>,
    /// Literal prefix. The body-length bounds below apply ONLY to a candidate
    /// that starts with this prefix (a differently-shaped credential is not
    /// owned by this rule and passes untouched).
    #[serde(default)]
    pub prefix: Option<String>,
    /// Minimum body byte length AFTER `prefix` (requires `prefix`).
    #[serde(default)]
    pub body_min_length: Option<usize>,
    /// Maximum body byte length AFTER `prefix` (requires `prefix`).
    #[serde(default)]
    pub body_max_length: Option<usize>,
}

impl CredentialShape {
    /// Validate the internal consistency of a declared shape (the single owner of
    /// these rules, was `credential_shapes::validate_shape_entries`). `detector_id`
    /// is only used to build a precise error message. Fails closed so a malformed
    /// per-detector shape is caught at load/build, never silently ignored.
    pub fn validate(&self, detector_id: &str) -> Result<(), String> {
        let has_constraint = self.exact_length.is_some()
            || self.prefix.is_some()
            || self.body_min_length.is_some()
            || self.body_max_length.is_some();
        if !has_constraint {
            return Err(format!(
                "credential shape for '{detector_id}' has no shape constraints"
            ));
        }
        if self.prefix.is_some()
            && self.exact_length.is_none()
            && self.body_min_length.is_none()
            && self.body_max_length.is_none()
        {
            return Err(format!(
                "credential shape for '{detector_id}' has a prefix but no length constraint"
            ));
        }
        if self.exact_length == Some(0) {
            return Err(format!(
                "credential shape for '{detector_id}' has exact_length=0"
            ));
        }
        if self.prefix.as_deref() == Some("") {
            return Err(format!(
                "credential shape for '{detector_id}' has an empty prefix"
            ));
        }
        if let (Some(minimum), Some(maximum)) = (self.body_min_length, self.body_max_length) {
            if minimum > maximum {
                return Err(format!(
                    "credential shape for '{detector_id}' has body_min_length greater than body_max_length"
                ));
            }
        }
        if (self.body_min_length.is_some() || self.body_max_length.is_some())
            && self.prefix.is_none()
        {
            return Err(format!(
                "credential shape for '{detector_id}' sets body length without a prefix"
            ));
        }
        if let (Some(exact_length), Some(prefix)) = (self.exact_length, self.prefix.as_deref()) {
            if let Some(minimum) = self.body_min_length {
                let minimum_total = prefix.len().checked_add(minimum).ok_or_else(|| {
                    format!("credential shape for '{detector_id}' overflows prefix plus body_min_length")
                })?;
                if exact_length < minimum_total {
                    return Err(format!(
                        "credential shape for '{detector_id}' has exact_length below prefix plus body_min_length"
                    ));
                }
            }
            if let Some(maximum) = self.body_max_length {
                let maximum_total = prefix.len().checked_add(maximum).ok_or_else(|| {
                    format!("credential shape for '{detector_id}' overflows prefix plus body_max_length")
                })?;
                if exact_length > maximum_total {
                    return Err(format!(
                        "credential shape for '{detector_id}' has exact_length above prefix plus body_max_length"
                    ));
                }
            }
        }
        Ok(())
    }
}

/// One inline detector self-test fixture (`[[detector.tests]]`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DetectorTestSpec {
    /// Text this detector MUST fire on.
    #[serde(default)]
    pub test_positive: Option<String>,
    /// Text this detector MUST NOT fire on.
    #[serde(default)]
    pub test_negative: Option<String>,
}

/// A regex pattern with optional capture group and description.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PatternSpec {
    /// Regular expression string (Rust flavor). Inter-keyword separator classes
    /// are canonicalized at load (see [`deserialize_canonical_regex`]).
    #[serde(deserialize_with = "deserialize_canonical_regex")]
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
#[serde(deny_unknown_fields)]
pub struct CompanionSpec {
    /// Field name used in verification templates (e.g. \`{{companion.secret_key}}\`).
    pub name: String,
    /// Regex to find the companion value nearby. Inter-keyword separator classes
    /// are canonicalized at load (see [`deserialize_canonical_regex`]).
    #[serde(deserialize_with = "deserialize_canonical_regex")]
    pub regex: String,
    /// Maximum line distance from the primary match.
    pub within_lines: usize,
    /// Whether this companion must be found to report the finding.
    #[serde(default)]
    pub required: bool,
}

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
    OobAndHttp,
    OobOnly,
    OobOptional,
}

/// A single step in a multi-step verification flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct HeaderSpec {
    pub name: String,
    pub value: String,
}

/// Authentication scheme for verification requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthSpec {
    None {},
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
        engine: ScriptEngine,
        code: String,
    },
}

/// Script interpreter names accepted by the detector TOML schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptEngine {
    Python3,
    Python,
    Node,
    Other(String),
}

impl ScriptEngine {
    pub const ALLOWED_FOR_VERIFY: &'static [&'static str] = &["python3", "python", "node"];

    pub fn as_str(&self) -> &str {
        match self {
            Self::Python3 => "python3",
            Self::Python => "python",
            Self::Node => "node",
            Self::Other(engine) => engine,
        }
    }

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    #[default]
    Info,
    ClientSafe,
    Low,
    Medium,
    High,
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
#[serde(deny_unknown_fields)]
pub struct DetectorFile {
    pub detector: DetectorSpec,
}
