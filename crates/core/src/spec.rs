//! Detector specification: TOML-based pattern definitions with regex, keywords,
//! verification endpoints, and companion patterns.

mod evidence;
pub(crate) mod load;
mod semantic;
mod validate;

mod entropy;
mod pattern;
mod policy;
mod verify_spec;

use serde::ser::Error as _;
use serde::{Deserialize, Serialize};

pub use entropy::{
    CanonicalHexKeyMaterialSpec, EntropyDetectionRole, EntropyFallbackClass,
    EntropyFallbackConfidenceSpec, EntropyFallbackMetadata, EntropyFloorBucket, EntropyShapeSpec,
    GenericAssignmentConfidenceSpec, ShapeCharset, ShapeGrouping,
};
pub use evidence::{ProviderEvidenceRole, ProviderEvidenceSensitivity};
pub use load::{
    load_detector_corpus, load_detectors, load_detectors_with_gate, read_detector_toml_file,
    LoadedDetectorCorpus, SpecError, DETECTOR_TOML_FILE_BYTES,
};
pub use semantic::{
    AnchorSemanticRole, CaptureSemanticRole, DetectorHardNegativeClass, DetectorSemanticPolicySpec,
    RequiredSemanticEvidence, SemanticSourceRole,
};
pub use validate::{validate_detector, validate_detector_for_corpus_schema, QualityIssue};

pub use pattern::{
    CompanionSpec, CredentialShape, DetectorRelationKind, DetectorRelationSpec, DetectorTestSpec,
    EvidenceDirection, EvidenceRequirement, EvidenceScope, EvidenceValueRelation, PatternSpec,
    SourceAdmissionSpec,
};
pub use policy::{
    DetectorBase64Alphabet, DetectorDecodeTransformSpec, DetectorMatchConfidenceSpec,
    DetectorMlMode, DetectorMlPolicySpec, DetectorPlausibilityPolicySpec,
    DetectorPostMatchConfidenceSpec, DetectorValidatorSpec,
};
pub use verify_spec::{
    AuthSpec, HeaderSpec, HttpMethod, OobPolicy, OobProtocol, OobSpec, ScriptEngine, Severity,
    StepSpec, SuccessPolicy, SuccessSpec, VerifySpec,
};
pub(crate) use verify_spec::migrate_legacy_success_policies;

/// Metadata field specification for verification results.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataSpec {
    /// Field name in the finding metadata map. Top-level verification metadata
    /// must name a supported [`ProviderEvidenceRole`]. Multi-step extraction
    /// may use a flow-local template name instead.
    pub name: String,
    /// `$`-rooted response selector, such as `$.account.email` or `$.orgs[0].name`.
    pub json_path: String,
    /// How a selected provider value may cross the reporting boundary.
    #[serde(default)]
    pub sensitivity: ProviderEvidenceSensitivity,
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
    /// Detector-owned policy for model scoring. The model implementation is a
    /// shared engine, but whether this detector invokes it, how model and
    /// structural evidence combine, and how much source context is extracted
    /// are properties of the secret type and therefore live in its TOML.
    /// TOML detectors must declare it. Programmatic `DetectorSpec::default()`
    /// disables both model paths until the caller chooses a policy.
    pub ml: DetectorMlPolicySpec,
    /// Detector-owned scoring policy for regex matches. Every signal weight,
    /// entropy tier, penalty, structural floor, and low-promise result is
    /// compiled into the detector execution plan.
    #[serde(default)]
    pub match_confidence: Option<DetectorMatchConfidenceSpec>,
    /// Detector-owned offline validation policy. Each entry declares both the
    /// validator primitive and every detector-specific parameter it needs.
    /// Shared scanner code supplies the primitive implementations, but it must
    /// not own token prefixes, field widths, confidence floors, or shape rules.
    #[serde(default)]
    pub validators: Vec<DetectorValidatorSpec>,
    /// Detector-owned admission policy for asymmetric evasion transforms.
    /// Shared decoders implement reverse and Caesar recovery, while each
    /// detector declares the literal prefixes that make those transforms
    /// eligible. Empty lists disable the corresponding transform for this
    /// detector. The compiled scanner unions only the declarations in its
    /// active corpus, so a custom corpus never inherits unrelated prefixes.
    #[serde(default)]
    pub decode_transforms: DetectorDecodeTransformSpec,
    /// Typed classification of the captured credential bytes. Current scan
    /// admission does not consume this declaration; `unknown` preserves
    /// current findings.
    #[serde(default, skip_serializing_if = "CaptureSemanticRole::is_unknown")]
    pub capture_role: CaptureSemanticRole,
    /// Typed classification of the detector anchor. Current scan admission
    /// does not consume this declaration; `unknown` preserves current findings.
    #[serde(default, skip_serializing_if = "AnchorSemanticRole::is_unknown")]
    pub anchor_role: AnchorSemanticRole,
    /// Detector-owned source-role declaration included in execution identity.
    /// Current scan admission does not consume this list. Empty preserves
    /// current findings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_source_roles: Vec<SemanticSourceRole>,
    /// Detector-owned evidence declaration included in execution identity.
    /// Current scan admission does not consume this list. Empty preserves
    /// current findings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_evidence: Vec<RequiredSemanticEvidence>,
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
    /// Relationships to findings emitted by other detectors in the same source,
    /// file, and revision.
    #[serde(default)]
    pub detector_relations: Vec<DetectorRelationSpec>,
    /// Positive source selectors. Every non-empty selector family must admit a
    /// finding before detector-specific matching can report it.
    #[serde(default)]
    pub source_admission: SourceAdmissionSpec,
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
    /// own TOML, the single source of truth for generic and weak-anchor entropy
    /// gates (there is no separate `rules/entropy-floors.toml`, no code table,
    /// no cross-detector policy borrowing). Length-bucketed: the FIRST bucket whose
    /// `max_len >= L` sets the floor for a candidate of length `L`; the last
    /// bucket omits `max_len` and is the catch-all. `max_len` must strictly
    /// increase. A generic-detector candidate whose Shannon entropy is BELOW the
    /// applicable floor is suppressed. Active entropy owners must declare at
    /// least one bucket.
    #[serde(default)]
    pub entropy_floor: Vec<EntropyFloorBucket>,
    // ── PER-DETECTOR RECALL/PRECISION KNOBS (migration 2026-07-07) ────────────
    // ARCHITECTURE LAW: there is NO global/overall entropy or recall/precision
    // gate applied uniformly to every candidate. EVERY threshold that affects
    // whether a candidate survives is a PER-DETECTOR field, OWNED HERE in the
    // detector's own TOML spec, exactly like `min_confidence`/`entropy_floor`
    // above. Optional representation preserves schema compatibility for
    // non-owning programmatic detectors, but active entropy owners must declare
    // every field and are compiled into concrete runtime policy. Reading two
    // places to understand one active detector's behavior is banned.
    /// Per-detector HIGH-entropy threshold (bits/byte), the keyword-independent
    /// bar. Active entropy owners must declare it.
    #[serde(default)]
    pub entropy_high: Option<f64>,
    /// Per-detector keyword-context (LOW) entropy threshold (bits/byte).
    /// Active entropy owners must declare it.
    #[serde(default)]
    pub entropy_low: Option<f64>,
    /// Per-detector VERY-high entropy threshold for keyword-free/isolated tokens.
    /// Active entropy owners must declare it.
    #[serde(default)]
    pub entropy_very_high: Option<f64>,
    /// Metadata used when this detector owns a synthetic entropy finding.
    /// Keeping the semantic class, emitted id, display name, and service beside
    /// the owning detector prevents scanner-side identity tables from drifting
    /// away from detector policy. Active entropy owners must declare it; a
    /// missing block is a compile-time configuration error, never a guessed
    /// scanner identity.
    #[serde(default)]
    pub entropy_fallback: Option<EntropyFallbackMetadata>,
    /// Detector-owned confidence tiers for synthetic entropy findings. The
    /// entropy engine supplies shared Shannon scoring, while each owning
    /// detector declares how that evidence maps to report confidence.
    #[serde(default)]
    pub entropy_fallback_confidence: Option<EntropyFallbackConfidenceSpec>,
    /// Detector-owned confidence policy for phase-two generic assignments.
    /// Context bases and evidence lifts compile with the detector that owns
    /// the assignment keyword.
    #[serde(default)]
    pub generic_assignment_confidence: Option<GenericAssignmentConfidenceSpec>,
    /// Corpus-level entropy roles owned by this detector. Roles make the
    /// shared entropy engine data-driven: it resolves keyword-free,
    /// isolated-bare, and unclaimed-keyword candidates from detector TOML
    /// instead of naming built-in detector IDs in scanner code. Each role may
    /// be claimed by at most one detector in a compiled corpus.
    #[serde(default)]
    pub entropy_roles: Vec<EntropyDetectionRole>,
    /// Per-detector keyword-free entropy threshold used for clearly sensitive
    /// paths. Active entropy owners must declare it; setting it lower than
    /// `entropy_very_high` is an explicit recall policy for files such as `.env`
    /// and secrets manifests, not a scanner-wide hidden discount.
    #[serde(default)]
    pub sensitive_path_entropy_very_high: Option<f64>,
    /// Detector-owned isolated entropy shapes. These are explicit structural
    /// exceptions to the broad keyword-free floor, such as a four-group
    /// lower-dash app password. Active entropy owners must declare the list.
    #[serde(default)]
    pub entropy_shapes: Vec<EntropyShapeSpec>,
    /// Complete detector-owned strict plausibility policy. Active entropy
    /// owners must declare the block; absence is valid only for detector paths
    /// that never invoke phase-2 plausibility scoring.
    #[serde(default)]
    pub plausibility: Option<DetectorPlausibilityPolicySpec>,
    /// Precedence when this detector owns entropy-fallback policy for one of
    /// its declared keywords. Active entropy owners must declare the value;
    /// regex detectors opt in by doing so. Higher values win overlapping
    /// keyword claims, so the policy decision is declared in detector TOML
    /// instead of depending on detector IDs or load order.
    #[serde(default)]
    pub entropy_policy_priority: Option<u16>,
    /// Per-detector BPE token-efficiency ceiling in UTF-8 bytes per
    /// `cl100k_base` token. Candidates above the ceiling are word-like and are
    /// suppressed after the cheaper entropy/shape gates. BPE-enabled entropy
    /// owners must declare it; an explicit scan override still has precedence.
    #[serde(default)]
    pub bpe_max_bytes_per_token: Option<f64>,
    /// Whether the BPE token-efficiency precision gate applies to this
    /// detector. Active entropy owners must declare the choice. `Some(false)`
    /// disables tokenization for detector families such as human-chosen
    /// passwords where word-like values are legitimate. A disabled detector
    /// must not also set a BPE ceiling.
    #[serde(default)]
    pub bpe_enabled: Option<bool>,
    /// Exact printable-hex character counts this phase-2 detector may retain
    /// after transport decoding. Keeping the lengths in detector TOML avoids a
    /// scanner-wide hardcoded key-width list. An empty list retains no decoded
    /// digest-shaped values.
    #[serde(default)]
    pub decoded_hex_key_material_lengths: Vec<usize>,
    /// Detector-owned canonical pure-hex key material. Phase-2 generic
    /// detectors scope lengths to exact assignment `keywords` or vendor
    /// `suffixes`. Regex detectors use length-only entries because their own
    /// matched pattern is already the anchor. This keeps digest-shaped recall
    /// exceptions in detector TOML instead of a scanner-wide length table.
    #[serde(default)]
    pub canonical_hex_key_material: Vec<CanonicalHexKeyMaterialSpec>,
    /// Per-detector minimum length for an anchor-free (keyword-free/isolated)
    /// candidate. Active entropy owners must declare it.
    #[serde(default)]
    pub keyword_free_min_len: Option<usize>,
    /// Per-detector minimum candidate length in UTF-8 bytes (any candidate this
    /// detector emits). Active entropy owners must declare it.
    #[serde(default)]
    pub min_len: Option<usize>,
    /// Per-detector maximum byte length for generic assignment values owned by
    /// this entropy policy, including regex detectors that also claim generic
    /// keywords through `entropy_policy_priority`.
    /// Values above this ceiling are rejected whole; they are never truncated
    /// into an apparently valid credential. Active phase-2 entropy owners must
    /// declare it.
    #[serde(default)]
    pub max_len: Option<usize>,
    /// Structural assignment suffixes for `<vendor>_<suffix>` names not claimed
    /// by an exact keyword. At most one phase-2 generic detector may declare a
    /// non-empty list; omission disables unlisted vendor suffixes.
    #[serde(default)]
    pub generic_vendor_suffixes: Vec<String>,
    /// Optional suffix segments accepted after an exact assignment keyword.
    /// At most one phase-2 generic detector may declare a non-empty list.
    #[serde(default)]
    pub generic_assignment_tail_suffixes: Vec<String>,
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
    /// Uppercase assignment-key fragments that identify public IDs rather than
    /// credentials for this detector's entropy path. Runtime matching is ASCII
    /// case-insensitive without allocating a normalized source line, so boundary
    /// bytes such as `=`, `:`, space, and quote are semantic. An empty list
    /// disables this detector-local suppression. TOML stores canonical uppercase.
    #[serde(default)]
    pub public_identifier_assignment_markers: Vec<String>,
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
    /// Per-detector weak-anchor classification, owned by this detector definition.
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
    /// Per-detector private-key-block classification, owned by this detector
    /// definition.
    ///
    /// `true` marks a detector whose match SPAN is an enclosing private-key block
    /// (`private-key`, `ssh-private-key`, `github-app-private-key`), a multi-line
    /// PEM/OpenSSH body. Resolution (`resolution::suppress_matches_nested_in_private_key_blocks`)
    /// fully suppresses any lower-specificity child finding nested inside such a
    /// span (an entropy/base64 hit on a line INSIDE the key body is not a second
    /// secret). A new private-key-block detector now declares this in its own TOML
    /// no code edit (and the whole story lives in the detector file).
    #[serde(default)]
    pub private_key_block: bool,
    /// Explicit detector specificity used when overlapping findings compete.
    ///
    /// Higher values win. The default `0` preserves equal standing; detectors
    /// that intentionally wrap a broader detector declare their precedence here
    /// instead of relying on detector ID spelling or input order.
    #[serde(default)]
    pub resolution_priority: i16,
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


impl DetectorSpec {
    /// Whether this detector supplies policy to the generic entropy engine.
    pub fn owns_entropy_policy(&self) -> bool {
        self.kind == DetectorKind::Phase2Generic || self.entropy_policy_priority.is_some()
    }

    /// Canonical semantic policy copied into compiled and persisted plans.
    pub fn semantic_policy(&self) -> DetectorSemanticPolicySpec {
        DetectorSemanticPolicySpec {
            capture_role: self.capture_role,
            anchor_role: self.anchor_role,
            allowed_source_roles: self.allowed_source_roles.clone(),
            required_evidence: self.required_evidence.clone(),
        }
    }

    /// Return the stable, redaction-safe declaration used by detector
    /// introspection surfaces.
    ///
    /// The projection starts from `DetectorSpec`'s own serializer. Fields that
    /// describe identity and matching stay at the top level; every other
    /// declared field moves into `policy`. This means a newly added detector
    /// field is included automatically instead of requiring a second manual
    /// field list in each CLI surface. Inline fixture bytes are replaced with
    /// positive/negative coverage booleans.
    pub fn introspection(&self) -> DetectorIntrospection<'_> {
        DetectorIntrospection { detector: self }
    }

    /// Whether this detector admits transport-decoded pure-hex key material at
    /// the exact declared character count.
    pub fn allows_decoded_hex_key_material(&self, value: &str) -> bool {
        value.bytes().all(|byte| byte.is_ascii_hexdigit())
            && self.decoded_hex_key_material_lengths.contains(&value.len())
    }

    /// Whether this detector admits a transport wrapper whose decoded payload
    /// is pure hex at the exact declared character count.
    pub fn allows_decoded_hex_key_material_len(&self, decoded_len: Option<usize>) -> bool {
        decoded_len.is_some_and(|length| self.decoded_hex_key_material_lengths.contains(&length))
    }

    /// Whether this detector's canonical-hex policy admits an exact assignment
    /// key and pure-hex value pair.
    pub fn allows_canonical_hex_key_material(&self, keyword: &str, value: &str) -> bool {
        if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return false;
        }
        self.canonical_hex_key_material.iter().any(|policy| {
            if !policy.lengths.contains(&value.len()) {
                return false;
            }
            if policy
                .excluded_keywords
                .iter()
                .any(|excluded| compact_assignment_keywords_equal(keyword, excluded))
            {
                return false;
            }
            policy
                .keywords
                .iter()
                .any(|owned_keyword| compact_assignment_keywords_equal(keyword, owned_keyword))
                || policy
                    .suffixes
                    .iter()
                    .any(|suffix| compact_assignment_keyword_ends_with(keyword, suffix))
        })
    }
}

/// Redaction-safe serialized view of one detector declaration.
pub struct DetectorIntrospection<'a> {
    detector: &'a DetectorSpec,
}

impl Serialize for DetectorIntrospection<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let serialized = serde_json::to_value(self.detector).map_err(S::Error::custom)?;
        let serde_json::Value::Object(mut declared) = serialized else {
            return Err(S::Error::custom(
                "DetectorSpec serialization must produce a JSON object",
            ));
        };

        let tests = declared
            .remove("tests")
            .ok_or_else(|| S::Error::custom("DetectorSpec serialization omitted tests"))?
            .as_array()
            .cloned()
            .ok_or_else(|| S::Error::custom("DetectorSpec tests must serialize as an array"))?;
        let test_contracts = tests
            .into_iter()
            .map(|test| {
                let positive = test
                    .get("test_positive")
                    .is_some_and(|value| !value.is_null());
                let negative = test
                    .get("test_negative")
                    .is_some_and(|value| !value.is_null());
                serde_json::json!({
                    "positive": positive,
                    "negative": negative,
                })
            })
            .collect();

        let verification = declared
            .remove("verify")
            .ok_or_else(|| S::Error::custom("DetectorSpec serialization omitted verify"))?;
        let has_verification = !verification.is_null();

        let mut output = serde_json::Map::new();
        for field in [
            "id",
            "name",
            "service",
            "severity",
            "keywords",
            "simdsieve_prefixes",
            "patterns",
            "companions",
        ] {
            let Some(value) = declared.remove(field) else {
                return Err(S::Error::custom(format!(
                    "DetectorSpec serialization omitted required field {field:?}"
                )));
            };
            output.insert(field.to_string(), value);
        }
        output.insert(
            "verify".to_string(),
            serde_json::Value::Bool(has_verification),
        );
        output.insert("verification".to_string(), verification);
        output.insert(
            "test_contracts".to_string(),
            serde_json::Value::Array(test_contracts),
        );
        output.insert("policy".to_string(), serde_json::Value::Object(declared));

        serde_json::Value::Object(output).serialize(serializer)
    }
}

fn compact_assignment_keywords_equal(left: &str, right: &str) -> bool {
    compact_assignment_keyword_bytes(left).eq(compact_assignment_keyword_bytes(right))
}

fn compact_assignment_keyword_ends_with(value: &str, suffix: &str) -> bool {
    let value_len = compact_assignment_keyword_bytes(value).count();
    let suffix_len = compact_assignment_keyword_bytes(suffix).count();
    // A suffix policy describes a vendor-prefixed assignment (`stripe_key`),
    // not the bare suffix itself (`key`). Exact names belong in `keywords`,
    // which keeps the policy explicit and preserves the bare-key digest gate.
    suffix_len > 0
        && value_len > suffix_len
        && compact_assignment_keyword_bytes(value)
            .skip(value_len - suffix_len)
            .eq(compact_assignment_keyword_bytes(suffix))
}

fn compact_assignment_keyword_bytes(value: &str) -> impl Iterator<Item = u8> + '_ {
    value
        .bytes()
        .filter(|byte| !matches!(byte, b'_' | b'-' | b'.'))
        .map(|byte| byte.to_ascii_lowercase())
}


/// Canonical file name for the directory-scoped detector corpus manifest.
pub const DETECTOR_CORPUS_MANIFEST_FILE: &str = "corpus.toml";

/// Oldest legacy detector schema this binary can migrate deterministically.
pub const DETECTOR_CORPUS_MIN_SCHEMA_VERSION: u32 = 1;

/// Detector schema authored and enforced by this binary.
pub const DETECTOR_CORPUS_SCHEMA_VERSION: u32 = 5;
pub(crate) const HARD_NEGATIVE_TEST_EVIDENCE_SCHEMA_VERSION: u32 = 5;

/// Highest newer detector schema this binary may inspect additively.
///
/// A corpus beyond this one-version compatibility window is rejected before
/// any detector is loaded.
pub const DETECTOR_CORPUS_MAX_FORWARD_SCHEMA_VERSION: u32 = DETECTOR_CORPUS_SCHEMA_VERSION + 1;

/// Directory-scoped compatibility contract for detector TOML files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorCorpusManifest {
    /// Schema version shared by every detector file in the directory.
    pub schema_version: u32,
}

/// Wrapping struct for a detector TOML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorFile {
    /// The single detector this file defines.
    pub detector: DetectorSpec,
}
