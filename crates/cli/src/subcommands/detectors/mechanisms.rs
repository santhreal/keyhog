//! The generated mechanism manifest: which recovery mechanisms each detector
//! actually declares.
//!
//! KeyHog advertises regex matching, structural validation, entropy scoring,
//! BPE token efficiency, decode recovery, companion confirmation, live
//! verification, and detector-owned suppression. Today an operator cannot ask
//! which of those a given detector uses. "Deep mode recovers X" is a claim
//! about the corpus that nothing in the product will confirm or deny for one
//! detector, so an unset field silently means "this mechanism is off here" and
//! looks identical to "this mechanism does not exist".
//!
//! This module answers the question by DERIVING the answer from the loaded
//! corpus. There is no per-detector table here: every mechanism is a predicate
//! over `DetectorSpec` fields, and the field that made it active is reported as
//! its evidence. Adding a detector, or turning a knob on in its TOML, changes
//! the manifest with no Rust edit, exactly like the detector corpus itself.
//!
//! A mechanism the corpus cannot currently express is reported with
//! `available: false` and the reason, rather than omitted. An operator reading
//! a manifest that silently lacks a row cannot tell "no detector uses this"
//! from "KeyHog cannot measure this yet", and those are different facts.

use keyhog_core::DetectorSpec;

/// One mechanism a detector can declare.
///
/// Ordered as the scan pipeline reaches them, so a manifest reads like the
/// path a candidate takes rather than like an alphabetized field dump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Mechanism {
    /// Phase-1 literal/regex anchors.
    Regex,
    /// Phase-2 keyword triggers for shapeless candidates.
    Keywords,
    /// Detector-owned structural contract: checksum, payload decode, exact
    /// shape, or a declared credential layout.
    Structure,
    /// Shannon entropy floors owned by this detector.
    Entropy,
    /// BPE token-efficiency precision gate.
    Bpe,
    /// Fixed-point byte-pair log-likelihood scoring.
    BytePairLikelihood,
    /// Detector-declared evasion recovery (reverse, Caesar) and transport
    /// decode admission.
    Decode,
    /// Secondary patterns that must confirm a match.
    Companions,
    /// Relationships to findings from other detectors in the same source.
    DetectorRelations,
    /// Live verification against the provider.
    Verification,
    /// Detector-owned suppression: allowlisted paths and values, stopwords,
    /// public-identifier markers.
    Suppression,
    /// Positive source selectors that gate where this detector may fire.
    SourceAdmission,
}

impl Mechanism {
    /// Stable machine-readable discriminator.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Regex => "regex",
            Self::Keywords => "keywords",
            Self::Structure => "structure",
            Self::Entropy => "entropy",
            Self::Bpe => "bpe",
            Self::BytePairLikelihood => "byte_pair_likelihood",
            Self::Decode => "decode",
            Self::Companions => "companions",
            Self::DetectorRelations => "detector_relations",
            Self::Verification => "verification",
            Self::Suppression => "suppression",
            Self::SourceAdmission => "source_admission",
        }
    }

    /// One calm sentence describing what the mechanism does.
    pub(crate) fn describe(self) -> &'static str {
        match self {
            Self::Regex => "phase-1 pattern anchors",
            Self::Keywords => "phase-2 keyword triggers for shapeless candidates",
            Self::Structure => {
                "offline structural proof: checksum, payload decode, or declared shape"
            }
            Self::Entropy => "detector-owned Shannon entropy floors",
            Self::Bpe => "BPE token-efficiency precision gate",
            Self::BytePairLikelihood => "fixed-point byte-pair log-likelihood scoring",
            Self::Decode => "detector-declared evasion and transport decode recovery",
            Self::Companions => "secondary patterns that confirm a match",
            Self::DetectorRelations => "relations to findings from other detectors",
            Self::Verification => "live verification against the provider",
            Self::Suppression => {
                "detector-owned allowlists, stopwords, and public-identifier markers"
            }
            Self::SourceAdmission => "positive source selectors gating where this detector fires",
        }
    }

    /// Every mechanism, in pipeline order.
    pub(crate) const ALL: [Self; 12] = [
        Self::Regex,
        Self::Keywords,
        Self::Structure,
        Self::Entropy,
        Self::Bpe,
        Self::BytePairLikelihood,
        Self::Decode,
        Self::Companions,
        Self::DetectorRelations,
        Self::Verification,
        Self::Suppression,
        Self::SourceAdmission,
    ];

    /// Why a mechanism cannot be reported per detector, or `None` when it can.
    ///
    /// A mechanism the corpus has no field for is a hole in the contract, not
    /// an absence of usage, and the manifest says which it is.
    pub(crate) fn unavailable_reason(self) -> Option<&'static str> {
        match self {
            Self::BytePairLikelihood => Some(
                "no detector field expresses this yet; the fixed-point byte-pair model \
                 is unbuilt (BACKLOG KH-850), so no detector can declare it and this \
                 row is structurally empty rather than measured",
            ),
            _ => None,
        }
    }
}

/// One mechanism a detector declares, with the field that proves it.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ActiveMechanism {
    /// Machine-readable mechanism id.
    pub(crate) id: &'static str,
    /// Detector TOML fields that made it active, in declaration order.
    pub(crate) evidence: Vec<&'static str>,
}

/// One detector's declared recovery contract.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct DetectorMechanisms {
    /// Stable detector id.
    pub(crate) id: String,
    /// Service namespace.
    pub(crate) service: String,
    /// `regex` or `phase2-generic`.
    pub(crate) kind: &'static str,
    /// Mechanisms this detector declares, in pipeline order.
    pub(crate) mechanisms: Vec<ActiveMechanism>,
}

/// One row of the corpus-wide summary.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct MechanismSummary {
    /// Machine-readable mechanism id.
    pub(crate) id: &'static str,
    /// What the mechanism does.
    pub(crate) description: &'static str,
    /// Whether the corpus can express this mechanism at all.
    pub(crate) available: bool,
    /// Why not, when `available` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) unavailable_reason: Option<&'static str>,
    /// Detectors declaring it.
    pub(crate) detectors: usize,
}

/// The complete manifest.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct MechanismManifest {
    /// Additive schema revision for this document.
    pub(crate) schema_version: u16,
    /// Detectors in the loaded corpus.
    pub(crate) detector_count: usize,
    /// Where the corpus came from: a directory path, or `embedded`.
    pub(crate) corpus: String,
    /// Corpus-wide counts, in pipeline order.
    pub(crate) summary: Vec<MechanismSummary>,
    /// Per-detector contracts, sorted by detector id.
    pub(crate) detectors: Vec<DetectorMechanisms>,
}

/// Additive revision of the manifest document. Bump when a field is added.
const MANIFEST_SCHEMA_VERSION: u16 = 1;

/// Derive the mechanisms one detector declares.
///
/// Every arm reads a `DetectorSpec` field. No detector id appears anywhere in
/// this function, so a new detector needs no code change to be described.
fn mechanisms_for(detector: &DetectorSpec) -> Vec<ActiveMechanism> {
    let mut out = Vec::new();
    let mut push = |mechanism: Mechanism, evidence: Vec<&'static str>| {
        if !evidence.is_empty() {
            out.push(ActiveMechanism {
                id: mechanism.as_str(),
                evidence,
            });
        }
    };

    push(
        Mechanism::Regex,
        field(!detector.patterns.is_empty(), "patterns"),
    );
    push(
        Mechanism::Keywords,
        field(!detector.keywords.is_empty(), "keywords"),
    );

    let mut structure = Vec::new();
    if !detector.validators.is_empty() {
        structure.push("validators");
    }
    if detector.credential_shape.is_some() {
        structure.push("credential_shape");
    }
    if !detector.entropy_shapes.is_empty() {
        structure.push("entropy_shapes");
    }
    push(Mechanism::Structure, structure);

    let mut entropy = Vec::new();
    if !detector.entropy_floor.is_empty() {
        entropy.push("entropy_floor");
    }
    if detector.entropy_high.is_some() {
        entropy.push("entropy_high");
    }
    if detector.entropy_low.is_some() {
        entropy.push("entropy_low");
    }
    if detector.entropy_very_high.is_some() {
        entropy.push("entropy_very_high");
    }
    if !detector.entropy_roles.is_empty() {
        entropy.push("entropy_roles");
    }
    push(Mechanism::Entropy, entropy);

    // `bpe_enabled = false` is a DECISION this detector made, not an absence,
    // so it counts as declaring the mechanism. The evidence names which way.
    let bpe = match detector.bpe_enabled {
        Some(true) => vec!["bpe_enabled = true"],
        Some(false) => vec!["bpe_enabled = false"],
        None => detector
            .bpe_max_bytes_per_token
            .map(|_| vec!["bpe_max_bytes_per_token"])
            .unwrap_or_default(), // LAW10: absent optional BPE settings correctly declare no BPE mechanism evidence in this manifest.
    };
    push(Mechanism::Bpe, bpe);

    let mut decode = Vec::new();
    if !detector.decode_transforms.reverse_prefixes.is_empty() {
        decode.push("decode_transforms.reverse_prefixes");
    }
    if !detector.decode_transforms.caesar_prefixes.is_empty() {
        decode.push("decode_transforms.caesar_prefixes");
    }
    if !detector.decoded_hex_key_material_lengths.is_empty() {
        decode.push("decoded_hex_key_material_lengths");
    }
    if !detector.canonical_hex_key_material.is_empty() {
        decode.push("canonical_hex_key_material");
    }
    push(Mechanism::Decode, decode);

    push(
        Mechanism::Companions,
        field(!detector.companions.is_empty(), "companions"),
    );
    push(
        Mechanism::DetectorRelations,
        field(
            !detector.detector_relations.is_empty(),
            "detector_relations",
        ),
    );
    push(
        Mechanism::Verification,
        field(detector.verify.is_some(), "verify"),
    );

    let mut suppression = Vec::new();
    if !detector.allowlist_paths.is_empty() {
        suppression.push("allowlist_paths");
    }
    if !detector.allowlist_values.is_empty() {
        suppression.push("allowlist_values");
    }
    if !detector.stopwords.is_empty() {
        suppression.push("stopwords");
    }
    if !detector.public_identifier_assignment_markers.is_empty() {
        suppression.push("public_identifier_assignment_markers");
    }
    push(Mechanism::Suppression, suppression);

    let admission = &detector.source_admission;
    let mut source = Vec::new();
    if !admission.path_patterns.is_empty() {
        source.push("source_admission.path_patterns");
    }
    if !admission.source_types.is_empty() {
        source.push("source_admission.source_types");
    }
    if !admission.file_extensions.is_empty() {
        source.push("source_admission.file_extensions");
    }
    push(Mechanism::SourceAdmission, source);

    out
}

#[inline]
fn field(active: bool, name: &'static str) -> Vec<&'static str> {
    if active {
        vec![name]
    } else {
        Vec::new()
    }
}

/// Build the manifest for a loaded corpus.
pub(crate) fn build(detectors: &[&DetectorSpec], corpus: String) -> MechanismManifest {
    let mut rows: Vec<DetectorMechanisms> = detectors
        .iter()
        .map(|detector| DetectorMechanisms {
            id: detector.id.clone(),
            service: detector.service.clone(),
            kind: match detector.kind {
                keyhog_core::DetectorKind::Regex => "regex",
                keyhog_core::DetectorKind::Phase2Generic => "phase2-generic",
            },
            mechanisms: mechanisms_for(detector),
        })
        .collect();
    rows.sort_by(|a, b| a.id.cmp(&b.id));

    let summary = Mechanism::ALL
        .iter()
        .map(|mechanism| {
            let id = mechanism.as_str();
            MechanismSummary {
                id,
                description: mechanism.describe(),
                available: mechanism.unavailable_reason().is_none(),
                unavailable_reason: mechanism.unavailable_reason(),
                detectors: rows
                    .iter()
                    .filter(|row| row.mechanisms.iter().any(|active| active.id == id))
                    .count(),
            }
        })
        .collect();

    MechanismManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        detector_count: rows.len(),
        corpus,
        summary,
        detectors: rows,
    }
}

/// Render the manifest as the human summary.
pub(crate) fn render_text(manifest: &MechanismManifest, out: &mut String) {
    use std::fmt::Write;

    let _ = writeln!(
        // LAW10: formatting into String is infallible; fmt::Write cannot return an operator-visible I/O failure.
        out,
        "Mechanism manifest: {} detectors from {}",
        manifest.detector_count,
        manifest.corpus
    );
    let _ = writeln!(out); // LAW10: formatting into String is infallible; fmt::Write cannot return an operator-visible I/O failure.
    for row in &manifest.summary {
        if row.available {
            let _ = writeln!(
                // LAW10: formatting into String is infallible; fmt::Write cannot return an operator-visible I/O failure.
                out,
                "  {:<22} {:>5}  {}",
                row.id,
                row.detectors,
                row.description
            );
        } else {
            let _ = writeln!(
                // LAW10: formatting into String is infallible; fmt::Write cannot return an operator-visible I/O failure.
                out,
                "  {:<22} {:>5}  {} [UNAVAILABLE: {}]",
                row.id,
                "n/a",
                row.description,
                "see --format json for the reason"
            );
        }
    }
    let _ = writeln!(out); // LAW10: formatting into String is infallible; fmt::Write cannot return an operator-visible I/O failure.

    // Every detector must list its mechanisms, so a detector that declares none
    // is named rather than dropped: an empty contract is a finding about the
    // corpus, not a row to hide.
    let silent: Vec<&str> = manifest
        .detectors
        .iter()
        .filter(|row| row.mechanisms.is_empty())
        .map(|row| row.id.as_str())
        .collect();
    if silent.is_empty() {
        let _ = writeln!(out, "Every detector declares at least one mechanism.");
    // LAW10: formatting into String is infallible; fmt::Write cannot return an operator-visible I/O failure.
    } else {
        let _ = writeln!(
            // LAW10: formatting into String is infallible; fmt::Write cannot return an operator-visible I/O failure.
            out,
            "{} detector(s) declare NO mechanism at all: {}",
            silent.len(),
            silent.join(", ")
        );
    }
}
