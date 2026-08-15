//! Cross-file credential correlation.
//!
//! A scanner reports one match at a time. An attacker does not use one match at
//! a time: they use the AWS access key from `main.tf` together with the secret
//! access key someone left in `.env`, and they notice that the "random" token in
//! `staging.yaml` is byte-for-byte the token in `prod.yaml`. Neither relationship
//! is visible in a flat findings list, and neither is reachable from inside a
//! detector: a `[[detector.companions]]` regex is bounded to a few lines of ONE
//! chunk, and per-detector dedup only folds repeats of the SAME detector into
//! `additional_locations`.
//!
//! This module runs after the scan, over the findings the report is about to
//! publish, and joins them into correlated groups:
//!
//! * [`CorrelationKind::ValueReuse`] - one credential digest at several distinct
//!   file paths, crossing detector boundaries.
//! * [`CorrelationKind::SplitComposite`] - a provider credential whose halves are
//!   separate detectors, planted in different files of one directory.
//!
//! Every service this join names lives in the Tier-B
//! `data/credential-correlation.toml` policy, never in a match arm here, so
//! extending provider coverage is a reviewable data edit.
//!
//! Correlation is strictly additive: it reads findings and returns a separate
//! list. It never adds, drops, reorders, or edits a finding, so a report
//! produced without correlation is byte-identical to one produced before this
//! module existed.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use crate::{hex_encode, CredentialHash, MatchLocation, Severity, VerifiedFinding};

/// How a correlation group was joined.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationKind {
    /// One credential value observed at several distinct file paths.
    ValueReuse,
    /// A composite provider credential whose required parts are split across
    /// different files.
    SplitComposite,
}

impl CorrelationKind {
    /// Stable machine-readable discriminator, shared by the JSON projection and
    /// the text renderer so the two can never disagree about a group's kind.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ValueReuse => "value_reuse",
            Self::SplitComposite => "split_composite",
        }
    }
}

/// Why one finding belongs to a correlation group.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationRole {
    /// The member carries the correlated credential value itself.
    SameValue,
    /// The member satisfies a required part of the composite credential.
    RequiredPart,
    /// The member satisfies an optional part of the composite credential.
    OptionalPart,
}

/// One place a correlated credential was seen.
///
/// Deliberately narrower than [`MatchLocation`]: a correlation answers "which
/// files does this reach", so it carries the path and line and drops chunk
/// offsets and commit provenance, which stay on the finding itself.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct CorrelatedLocation {
    /// File path, object key, or logical path of the match.
    pub file_path: String,
    /// One-based line number when the source knew one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
}

/// One finding participating in a correlation group.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CorrelatedMember {
    /// Detector that produced the member finding.
    pub detector_id: String,
    /// Human-readable detector name.
    pub detector_name: String,
    /// Service namespace of the member detector.
    pub service: String,
    /// Severity the member finding carries on its own.
    pub severity: Severity,
    /// Why this member is in the group.
    pub role: CorrelationRole,
    /// Redacted credential preview, identical to the member finding's.
    pub credential_redacted: String,
    /// Hex SHA-256 digest of the member credential, the join key for value
    /// reuse and the stable link back to the finding it came from.
    pub credential_hash: String,
    /// Member evidence score before correlation lifted it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_score: Option<f64>,
    /// Locations of this member that fall inside the group's scope.
    pub locations: Vec<CorrelatedLocation>,
}

/// A credential risk assembled from several findings.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CorrelatedCredential {
    /// Stable identifier for the group, unique within one report.
    pub id: String,
    /// How the group was joined.
    pub kind: CorrelationKind,
    /// One-line operator-facing summary.
    pub title: String,
    /// Service namespace, or `multiple` when members disagree.
    pub service: String,
    /// Group severity: the strongest member severity, raised to the composite's
    /// declared severity when the Tier-B policy declares a higher one.
    pub severity: Severity,
    /// Correlated evidence score: the strongest member score lifted by the
    /// Tier-B bonus and clamped to the configured ceiling. Absent when no
    /// member carries an evidence score.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_score: Option<f64>,
    /// Strongest evidence score any single member had before the lift, so a
    /// reader can see exactly what correlation added.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strongest_member_evidence_score: Option<f64>,
    /// Directory the composite parts share. Absent for value reuse, which is
    /// scoped to the whole scan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Number of distinct files the group spans.
    pub file_count: usize,
    /// What the correlation means for an operator, from Tier-B data.
    pub impact: String,
    /// Member findings, sorted by detector id then credential digest.
    pub members: Vec<CorrelatedMember>,
    /// Union of every member location in the group, sorted by path then line.
    pub locations: Vec<CorrelatedLocation>,
}

/// Tunables shared by every correlation join.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CorrelationSettings {
    reuse_min_files: usize,
    reuse_confidence_bonus: f64,
    max_confidence: f64,
    reuse_impact: String,
}

/// One composite provider credential whose halves are separate detectors.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CompositeSpec {
    id: String,
    service: String,
    name: String,
    severity: Severity,
    required: Vec<String>,
    #[serde(default)]
    optional: Vec<String>,
    confidence_bonus: f64,
    impact: String,
}

/// The parsed Tier-B correlation policy.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CorrelationPolicy {
    settings: CorrelationSettings,
    #[serde(default)]
    composite: Vec<CompositeSpec>,
}

/// The compiled-in policy. `include_str!` makes an invalid document a BUILD bug,
/// never a runtime condition the operator can act on, so the initializer panics
/// rather than degrading to an empty policy: an empty policy would silently
/// report zero correlations on a repo that has them, which is exactly the
/// fail-silent shape Law 10 forbids.
#[allow(clippy::panic)]
static POLICY: LazyLock<CorrelationPolicy> = LazyLock::new(|| {
    match parse_policy(
        include_str!("../data/credential-correlation.toml"),
        "<embedded data/credential-correlation.toml>",
    ) {
        Ok(policy) => policy,
        Err(error) => panic!(
            "keyhog: credential-correlation policy '<embedded \
             data/credential-correlation.toml>' is invalid: {error}. \
             Fix: correct crates/core/data/credential-correlation.toml and rebuild"
        ),
    }
});

/// Parse and validate one correlation policy document.
///
/// Returned as `Err` rather than panicking so the same validation runs over
/// candidate documents in tests without taking the process down.
fn parse_policy(raw: &str, origin: &str) -> Result<CorrelationPolicy, String> {
    let policy = toml::from_str::<CorrelationPolicy>(raw)
        .map_err(|error| format!("failed to parse {origin}: {error}"))?;
    validate_policy(&policy, origin)?;
    Ok(policy)
}

/// Fail closed on a policy that would silently misbehave: a reuse threshold
/// below two is not a cross-file join at all, a non-positive bonus makes
/// correlation claim corroboration it did not add, a required list shorter than
/// two parts is not a composite, and a duplicate part id means one of the rows
/// can never be satisfied the way its author intended.
fn validate_policy(policy: &CorrelationPolicy, origin: &str) -> Result<(), String> {
    let settings = &policy.settings;
    if settings.reuse_min_files < 2 {
        return Err(format!(
            "{origin} [settings] reuse_min_files must be at least 2, got {}",
            settings.reuse_min_files
        ));
    }
    if !(settings.reuse_confidence_bonus > 0.0 && settings.reuse_confidence_bonus <= 1.0) {
        return Err(format!(
            "{origin} [settings] reuse_confidence_bonus must be in (0.0, 1.0], got {}",
            settings.reuse_confidence_bonus
        ));
    }
    if !(settings.max_confidence > 0.0 && settings.max_confidence <= 1.0) {
        return Err(format!(
            "{origin} [settings] max_confidence must be in (0.0, 1.0], got {}",
            settings.max_confidence
        ));
    }
    if settings.reuse_impact.trim().is_empty() {
        return Err(format!(
            "{origin} [settings] reuse_impact must not be empty"
        ));
    }

    let mut seen_ids = BTreeSet::new();
    for composite in &policy.composite {
        let id = composite.id.trim();
        if id.is_empty() {
            return Err(format!("{origin} [[composite]] has an empty id"));
        }
        if !seen_ids.insert(id) {
            return Err(format!("{origin} [[composite]] duplicate id {id:?}"));
        }
        if composite.service.trim().is_empty() {
            return Err(format!(
                "{origin} [[composite]] {id:?} has an empty service"
            ));
        }
        if composite.name.trim().is_empty() {
            return Err(format!("{origin} [[composite]] {id:?} has an empty name"));
        }
        if composite.impact.trim().is_empty() {
            return Err(format!("{origin} [[composite]] {id:?} has an empty impact"));
        }
        if composite.required.len() < 2 {
            return Err(format!(
                "{origin} [[composite]] {id:?} needs at least 2 required parts, got {}",
                composite.required.len()
            ));
        }
        if !(composite.confidence_bonus > 0.0 && composite.confidence_bonus <= 1.0) {
            return Err(format!(
                "{origin} [[composite]] {id:?} confidence_bonus must be in (0.0, 1.0], got {}",
                composite.confidence_bonus
            ));
        }
        let mut seen_parts = BTreeSet::new();
        for part in composite.required.iter().chain(composite.optional.iter()) {
            let part = part.trim();
            if part.is_empty() {
                return Err(format!(
                    "{origin} [[composite]] {id:?} has an empty part id"
                ));
            }
            if !seen_parts.insert(part) {
                return Err(format!(
                    "{origin} [[composite]] {id:?} lists part {part:?} more than once"
                ));
            }
        }
    }
    Ok(())
}

/// Every detector id any composite row names, sorted and deduplicated.
///
/// Exposed so a corpus-integrity check can prove the Tier-B policy only names
/// detectors that actually ship: a typo would otherwise make a whole composite
/// silently unsatisfiable.
#[must_use]
pub fn correlation_composite_part_ids() -> Vec<&'static str> {
    let mut ids: Vec<&'static str> = POLICY
        .composite
        .iter()
        .flat_map(|composite| composite.required.iter().chain(composite.optional.iter()))
        .map(String::as_str)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// Validate a candidate correlation policy document.
///
/// The shipped policy is compiled in and validated at first use; this entry
/// point exists so the same fail-closed rules can be exercised against
/// hand-written documents without a rebuild.
///
/// # Errors
///
/// Returns the human-readable reason the document was rejected.
pub fn validate_correlation_policy(raw: &str, origin: &str) -> Result<(), String> {
    parse_policy(raw, origin).map(|_| ())
}

/// Directory portion of a scanned path, or `.` for a path with no separator.
///
/// Splits on both separators unconditionally: a report can carry Windows paths
/// while running on a POSIX host (git history, remote sources, a report
/// re-rendered elsewhere), so keying on the host separator alone would put
/// `a\b.env` and `a\c.env` in different scopes.
fn parent_dir(path: &str) -> &str {
    match path.rfind(['/', '\\']) {
        Some(0) => &path[..1],
        Some(index) => &path[..index],
        None => ".",
    }
}

/// Locations a finding occupies: its primary plus every deduplicated repeat.
fn finding_locations(finding: &VerifiedFinding) -> impl Iterator<Item = &MatchLocation> {
    std::iter::once(&finding.location).chain(finding.additional_locations.iter())
}

/// Largest evidence score in an iterator of member findings, ignoring members
/// that never scored one.
fn strongest_evidence_score<'a>(members: impl Iterator<Item = &'a VerifiedFinding>) -> Option<f64> {
    members
        .filter_map(|finding| finding.evidence_score)
        .fold(None, |best: Option<f64>, value| {
            Some(best.map_or(value, |current| current.max(value)))
        })
}

/// Apply a Tier-B bonus to the strongest member evidence score, clamped to the
/// configured ceiling. A member already at the ceiling keeps its value.
fn lift(strongest: Option<f64>, bonus: f64) -> Option<f64> {
    strongest.map(|value| {
        (value + bonus)
            .min(POLICY.settings.max_confidence)
            .max(value)
    })
}

/// Render a member for a correlation group, keeping only the locations that
/// fall inside `scope` when a scope is given.
fn member_of(
    finding: &VerifiedFinding,
    role: CorrelationRole,
    scope: Option<&str>,
) -> CorrelatedMember {
    let mut locations: Vec<CorrelatedLocation> = finding_locations(finding)
        .filter_map(|location| {
            let path = location.file_path.as_deref()?;
            if scope.is_some_and(|dir| parent_dir(path) != dir) {
                return None;
            }
            Some(CorrelatedLocation {
                file_path: path.to_string(),
                line: location.line,
            })
        })
        .collect();
    locations.sort();
    locations.dedup();
    CorrelatedMember {
        detector_id: finding.detector_id.to_string(),
        detector_name: finding.detector_name.to_string(),
        service: finding.service.to_string(),
        severity: finding.severity,
        role,
        credential_redacted: finding.credential_redacted.to_string(),
        credential_hash: hex_encode(finding.credential_hash),
        evidence_score: finding.evidence_score,
        locations,
    }
}

/// Union of member locations, sorted and deduplicated.
fn union_locations(members: &[CorrelatedMember]) -> Vec<CorrelatedLocation> {
    let mut locations: Vec<CorrelatedLocation> = members
        .iter()
        .flat_map(|member| member.locations.iter().cloned())
        .collect();
    locations.sort();
    locations.dedup();
    locations
}

/// Distinct file paths a location list touches.
fn distinct_files(locations: &[CorrelatedLocation]) -> usize {
    locations
        .iter()
        .map(|location| location.file_path.as_str())
        .collect::<BTreeSet<_>>()
        .len()
}

/// Single service shared by every member, or `multiple` when they disagree.
fn shared_service(members: &[CorrelatedMember]) -> String {
    let mut services = members.iter().map(|member| member.service.as_str());
    let Some(first) = services.next() else {
        return "multiple".to_string();
    };
    if services.all(|service| service == first) {
        first.to_string()
    } else {
        "multiple".to_string()
    }
}

/// Correlate the findings a report is about to publish.
///
/// Returns a deterministically ordered list: identical findings always produce
/// identical bytes, independent of scan order, filesystem enumeration, or
/// thread scheduling.
#[must_use]
pub fn correlate_findings(findings: &[VerifiedFinding]) -> Vec<CorrelatedCredential> {
    let mut correlations = value_reuse_groups(findings);
    correlations.extend(split_composite_groups(findings));
    correlations.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| right.severity.cmp(&left.severity))
            .then_with(|| left.service.cmp(&right.service))
            .then_with(|| left.id.cmp(&right.id))
    });
    correlations
}

/// Join findings that carry the same credential digest at several file paths.
fn value_reuse_groups(findings: &[VerifiedFinding]) -> Vec<CorrelatedCredential> {
    let mut by_digest: BTreeMap<CredentialHash, Vec<&VerifiedFinding>> = BTreeMap::new();
    for finding in findings {
        by_digest
            .entry(finding.credential_hash)
            .or_default()
            .push(finding);
    }

    let mut groups = Vec::new();
    for (digest, mut group) in by_digest {
        group.sort_by(|left, right| {
            left.detector_id
                .cmp(&right.detector_id)
                .then_with(|| left.location.file_path.cmp(&right.location.file_path))
                .then_with(|| left.location.line.cmp(&right.location.line))
        });
        let members: Vec<CorrelatedMember> = group
            .iter()
            .map(|finding| member_of(finding, CorrelationRole::SameValue, None))
            .collect();
        let locations = union_locations(&members);
        let file_count = distinct_files(&locations);
        if file_count < POLICY.settings.reuse_min_files {
            continue;
        }
        let detectors: BTreeSet<&str> = members
            .iter()
            .map(|member| member.detector_id.as_str())
            .collect();
        let title = if detectors.len() > 1 {
            format!(
                "One secret value matched by {} detectors across {file_count} files",
                detectors.len()
            )
        } else {
            format!(
                "{} value reused across {file_count} files",
                members
                    .first()
                    .map_or("Credential", |member| member.detector_name.as_str())
            )
        };
        let strongest = strongest_evidence_score(group.iter().copied());
        let severity = members
            .iter()
            .map(|member| member.severity)
            .max()
            .unwrap_or_default(); // LAW10: an empty correlated member set has no severity; this display model default cannot remove source findings.
        groups.push(CorrelatedCredential {
            id: format!("reuse:{}", hex_encode(digest)),
            kind: CorrelationKind::ValueReuse,
            title,
            service: shared_service(&members),
            severity,
            evidence_score: lift(strongest, POLICY.settings.reuse_confidence_bonus),
            strongest_member_evidence_score: strongest,
            scope: None,
            file_count,
            impact: POLICY.settings.reuse_impact.clone(),
            members,
            locations,
        });
    }
    groups
}

/// Per-directory index used by the composite join: which credential digests each
/// detector produced inside each directory.
type DirectoryIndex<'a> = BTreeMap<&'a str, BTreeMap<&'a str, BTreeSet<CredentialHash>>>;

/// Join composite provider credentials whose required parts sit in different
/// files of one directory.
fn split_composite_groups(findings: &[VerifiedFinding]) -> Vec<CorrelatedCredential> {
    let mut index: DirectoryIndex<'_> = BTreeMap::new();
    let mut by_part: BTreeMap<(&str, CredentialHash), &VerifiedFinding> = BTreeMap::new();
    for finding in findings {
        by_part.insert((&finding.detector_id, finding.credential_hash), finding);
        for location in finding_locations(finding) {
            let Some(path) = location.file_path.as_deref() else {
                continue;
            };
            index
                .entry(parent_dir(path))
                .or_default()
                .entry(&finding.detector_id)
                .or_default()
                .insert(finding.credential_hash);
        }
    }

    let mut groups = Vec::new();
    for (directory, detectors) in &index {
        for composite in &POLICY.composite {
            let Some(group) = composite_group(composite, directory, detectors, &by_part) else {
                continue;
            };
            groups.push(group);
        }
    }
    groups
}

/// Build one composite group for `directory`, or `None` when the directory does
/// not satisfy the composite unambiguously.
fn composite_group(
    composite: &CompositeSpec,
    directory: &str,
    detectors: &BTreeMap<&str, BTreeSet<CredentialHash>>,
    by_part: &BTreeMap<(&str, CredentialHash), &VerifiedFinding>,
) -> Option<CorrelatedCredential> {
    let mut members = Vec::with_capacity(composite.required.len() + composite.optional.len());
    let mut sources = Vec::with_capacity(composite.required.len());

    for part in &composite.required {
        let digests = detectors.get(part.as_str())?;
        // Two candidate access keys and three candidate secrets sharing a
        // directory is an ambiguous pairing. Report nothing rather than assert a
        // pair that may not exist.
        let [digest] = digests.iter().copied().collect::<Vec<_>>()[..] else {
            return None;
        };
        let finding = by_part.get(&(part.as_str(), digest))?;
        let member = member_of(finding, CorrelationRole::RequiredPart, Some(directory));
        sources.push(*finding);
        members.push(member);
    }

    // The whole point is the SPLIT: when one file already holds every required
    // part, the detector's own companion regex covers it and a correlation would
    // only restate the finding.
    let mut shared: Option<BTreeSet<&str>> = None;
    for member in &members {
        let files: BTreeSet<&str> = member
            .locations
            .iter()
            .map(|location| location.file_path.as_str())
            .collect();
        shared = Some(match shared {
            None => files,
            Some(current) => current.intersection(&files).copied().collect(),
        });
    }
    if shared.is_none_or(|files| !files.is_empty()) {
        return None;
    }

    for part in &composite.optional {
        let Some(digests) = detectors.get(part.as_str()) else {
            continue;
        };
        let [digest] = digests.iter().copied().collect::<Vec<_>>()[..] else {
            continue;
        };
        let Some(finding) = by_part.get(&(part.as_str(), digest)) else {
            continue;
        };
        sources.push(*finding);
        members.push(member_of(
            finding,
            CorrelationRole::OptionalPart,
            Some(directory),
        ));
    }

    members.sort_by(|left, right| {
        left.detector_id
            .cmp(&right.detector_id)
            .then_with(|| left.credential_hash.cmp(&right.credential_hash))
    });
    let locations = union_locations(&members);
    let file_count = distinct_files(&locations);
    let strongest = strongest_evidence_score(sources.into_iter());
    let severity = members
        .iter()
        .map(|member| member.severity)
        .max()
        .unwrap_or_default() // LAW10: absent companion severity leaves the composite's own severity authoritative; all member findings remain retained.
        .max(composite.severity);
    Some(CorrelatedCredential {
        id: format!("composite:{}@{directory}", composite.id),
        kind: CorrelationKind::SplitComposite,
        title: format!("{} split across {file_count} files", composite.name),
        service: composite.service.clone(),
        severity,
        evidence_score: lift(strongest, composite.confidence_bonus),
        strongest_member_evidence_score: strongest,
        scope: Some(directory.to_string()),
        file_count,
        impact: composite.impact.clone(),
        members,
        locations,
    })
}
