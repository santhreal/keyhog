//! Exact real-corpus measurement for the production bigram prefilter.

use crate::args::BloomDiagnosticArgs;
use anyhow::{bail, Context, Result};
use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{BigramPrefilterState, CompiledScanner, ScanBackend};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::path::{Component, Path};
use std::process::ExitCode;

const FIXTURE_SCHEMA: &str = "keyhog-bloom-corpus-v1";
const RESULT_SCHEMA: &str = "bloom-evidence-v1";
const UNAVAILABLE_SOURCE_FILE_MISSING: &str = "source-file-missing";
const MAX_BATCH_INPUTS: usize = 1_024;
const MAX_BATCH_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BloomCorpusFixture {
    schema_version: String,
    corpus_name: String,
    corpus_revision: String,
    declared_input_count: u64,
    unavailable_inputs: Vec<UnavailableInput>,
    inputs: Vec<BloomFixtureInput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnavailableInput {
    id: String,
    path: String,
    category: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BloomFixtureInput {
    id: String,
    path: String,
    labels: Vec<String>,
    line_start: usize,
    line_end: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BloomCorpusResult {
    pub schema_version: String,
    pub corpus_name: String,
    pub corpus_revision: String,
    pub fixture_sha256: String,
    pub corpus_sha256: String,
    pub detector_corpus_sha256: String,
    pub scanner_detector_digest: String,
    pub declared_input_count: u64,
    pub unavailable_input_count: u64,
    pub unavailable_reason_counts: BTreeMap<String, u64>,
    pub input_count: u64,
    pub eligible_input_count: u64,
    pub admitted_input_count: u64,
    pub rejected_input_count: u64,
    pub rejection_basis_points: u16,
    pub populated_slots: u32,
    pub total_slots: u32,
    pub saturation_threshold_slots: u32,
    pub density_basis_points: u16,
    pub state: String,
    pub enabled_finding_count: u64,
    pub bypass_finding_count: u64,
    pub enabled_findings_sha256: String,
    pub bypass_findings_sha256: String,
    pub findings_identical: bool,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FindingIdentity {
    detector_id: String,
    file_path: Option<String>,
    line: Option<usize>,
    span_start: usize,
    span_end: usize,
    credential_sha256: String,
}

#[derive(Default)]
struct MeasurementTotals {
    input_count: u64,
    eligible_input_count: u64,
    rejected_input_count: u64,
    enabled_findings: Vec<FindingIdentity>,
    bypass_findings: Vec<FindingIdentity>,
}

pub(crate) fn run(args: BloomDiagnosticArgs) -> Result<ExitCode> {
    let fixture_bytes = std::fs::read(&args.fixture)
        .with_context(|| format!("read Bloom corpus fixture {}", args.fixture.display()))?;
    let fixture_sha256 = sha256_hex(&fixture_bytes);
    let mut fixture: BloomCorpusFixture = serde_json::from_slice(&fixture_bytes)
        .with_context(|| format!("parse Bloom corpus fixture {}", args.fixture.display()))?;
    validate_fixture(&fixture)?;
    fixture.inputs.sort_by(|left, right| {
        (&left.path, left.line_start, left.line_end, &left.id).cmp(&(
            &right.path,
            right.line_start,
            right.line_end,
            &right.id,
        ))
    });

    let corpus_root = std::fs::canonicalize(&args.corpus_root).with_context(|| {
        format!(
            "resolve Bloom corpus root {} (no fallback corpus is used)",
            args.corpus_root.display()
        )
    })?;
    let detectors = keyhog_core::embedded_detector_specs().to_vec();
    let detector_corpus_sha256 = keyhog_core::hex_encode(
        keyhog_core::compute_detector_corpus_digest(&detectors)
            .context("compute embedded detector corpus SHA-256")?,
    );
    let scanner = CompiledScanner::compile(detectors)
        .context("compile embedded detector corpus for Bloom differential")?;
    let enabled_digest = scanner.runtime_status().detector_digest;

    let status = scanner.bigram_prefilter_status();
    let mut corpus_hasher = Sha256::new();
    hash_field(&mut corpus_hasher, fixture.corpus_name.as_bytes());
    hash_field(&mut corpus_hasher, fixture.corpus_revision.as_bytes());
    let mut totals = MeasurementTotals::default();
    let mut batch = Vec::with_capacity(MAX_BATCH_INPUTS);
    let mut batch_bytes = 0usize;
    let mut loaded_path = String::new();
    let mut loaded_bytes = Vec::new();
    let mut loaded_line_offsets = Vec::new();

    for input in &fixture.inputs {
        if loaded_path != input.path {
            let relative = Path::new(&input.path);
            if !safe_relative_path(relative) {
                bail!(
                    "Bloom corpus fixture input is not a safe relative path: {}",
                    input.path
                );
            }
            let resolved =
                std::fs::canonicalize(corpus_root.join(relative)).with_context(|| {
                    format!(
                        "Bloom corpus input unavailable: {} (no fallback corpus is used)",
                        input.path
                    )
                })?;
            if !resolved.starts_with(&corpus_root) {
                bail!(
                    "Bloom corpus fixture input escapes corpus root: {}",
                    input.path
                );
            }
            loaded_bytes = std::fs::read(&resolved)
                .with_context(|| format!("read Bloom corpus input {}", input.path))?;
            loaded_line_offsets = line_offsets(&loaded_bytes);
            loaded_path.clone_from(&input.path);
        }
        let (start, end) = line_span(
            &loaded_line_offsets,
            loaded_bytes.len(),
            input.line_start,
            input.line_end,
        )
        .with_context(|| {
            format!(
                "resolve Bloom corpus line span {}:{}-{}",
                input.path, input.line_start, input.line_end
            )
        })?;
        let data = String::from_utf8_lossy(&loaded_bytes[start..end]).into_owned();
        hash_field(&mut corpus_hasher, input.id.as_bytes());
        hash_field(&mut corpus_hasher, input.path.as_bytes());
        hash_field(&mut corpus_hasher, input.line_start.to_string().as_bytes());
        hash_field(&mut corpus_hasher, input.line_end.to_string().as_bytes());
        for label in &input.labels {
            hash_field(&mut corpus_hasher, label.as_bytes());
        }
        hash_field(&mut corpus_hasher, data.as_bytes());
        batch_bytes = batch_bytes.saturating_add(data.len());
        batch.push(Chunk {
            data: data.into(),
            metadata: ChunkMetadata {
                base_offset: start,
                base_line: input.line_start.saturating_sub(1),
                source_type: "bloom-diagnostic".into(),
                ctime_ns: None,
                path: Some(format!("{}#{}", input.path, input.id).into()),
                commit: None,
                author: None,
                date: None,
                mtime_ns: None,
                size_bytes: None,
                decoded_span: None,
            },
        });
        if batch.len() >= MAX_BATCH_INPUTS || batch_bytes >= MAX_BATCH_BYTES {
            measure_batch(&scanner, &fixture.corpus_name, &batch, &mut totals)?;
            batch.clear();
            batch_bytes = 0;
        }
    }
    if !batch.is_empty() {
        measure_batch(&scanner, &fixture.corpus_name, &batch, &mut totals)?;
    }

    totals.enabled_findings.sort();
    totals.enabled_findings.dedup();
    totals.bypass_findings.sort();
    totals.bypass_findings.dedup();
    let findings_identical = totals.enabled_findings == totals.bypass_findings;
    let enabled_findings_sha256 = finding_digest(&totals.enabled_findings);
    let bypass_findings_sha256 = finding_digest(&totals.bypass_findings);
    if !findings_identical {
        let missing_from_enabled = totals
            .bypass_findings
            .iter()
            .filter(|finding| totals.enabled_findings.binary_search(finding).is_err())
            .take(8)
            .collect::<Vec<_>>();
        let missing_from_bypass = totals
            .enabled_findings
            .iter()
            .filter(|finding| totals.bypass_findings.binary_search(finding).is_err())
            .take(8)
            .collect::<Vec<_>>();
        bail!(
            "Bloom differential found a finding mismatch: enabled={} ({enabled_findings_sha256}), bypass={} ({bypass_findings_sha256}); missing from enabled: {missing_from_enabled:?}; missing from bypass: {missing_from_bypass:?}",
            totals.enabled_findings.len(),
            totals.bypass_findings.len(),
        );
    }
    if totals.rejected_input_count == 0 {
        bail!(
            "Bloom rejected 0 of {} named corpus inputs; refusing to publish ineffective evidence",
            totals.input_count
        );
    }

    let rejection_basis_points =
        share_basis_points(totals.rejected_input_count, totals.input_count);
    let unavailable_reason_counts =
        fixture
            .unavailable_inputs
            .iter()
            .fold(BTreeMap::new(), |mut counts, unavailable| {
                *counts.entry(unavailable.category.clone()).or_insert(0) += 1;
                counts
            });
    let result = BloomCorpusResult {
        schema_version: RESULT_SCHEMA.to_string(),
        corpus_name: fixture.corpus_name,
        corpus_revision: fixture.corpus_revision,
        fixture_sha256,
        corpus_sha256: keyhog_core::hex_encode(corpus_hasher.finalize()),
        detector_corpus_sha256,
        scanner_detector_digest: format!("{enabled_digest:016x}"),
        declared_input_count: fixture.declared_input_count,
        unavailable_input_count: fixture.unavailable_inputs.len() as u64,
        unavailable_reason_counts,
        input_count: totals.input_count,
        eligible_input_count: totals.eligible_input_count,
        admitted_input_count: totals
            .input_count
            .saturating_sub(totals.rejected_input_count),
        rejected_input_count: totals.rejected_input_count,
        rejection_basis_points,
        populated_slots: status.populated_slots,
        total_slots: status.total_slots,
        saturation_threshold_slots: status.saturation_threshold_slots,
        density_basis_points: status.density_basis_points,
        state: prefilter_state_label(status.state).to_string(),
        enabled_finding_count: totals.enabled_findings.len() as u64,
        bypass_finding_count: totals.bypass_findings.len() as u64,
        enabled_findings_sha256,
        bypass_findings_sha256,
        findings_identical,
    };
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(ExitCode::SUCCESS)
}

fn validate_fixture(fixture: &BloomCorpusFixture) -> Result<()> {
    if fixture.schema_version != FIXTURE_SCHEMA {
        bail!(
            "unsupported Bloom corpus fixture schema {:?}; expected {FIXTURE_SCHEMA}",
            fixture.schema_version
        );
    }
    if fixture.corpus_name.trim().is_empty() || fixture.corpus_revision.trim().is_empty() {
        bail!("Bloom corpus fixture must name a corpus and revision");
    }
    if fixture.inputs.is_empty() {
        bail!("Bloom corpus fixture contains no measurable inputs");
    }
    let actual_declared = fixture
        .inputs
        .len()
        .saturating_add(fixture.unavailable_inputs.len());
    if fixture.declared_input_count != actual_declared as u64 {
        bail!(
            "Bloom corpus fixture count mismatch: declared {}, listed {}",
            fixture.declared_input_count,
            actual_declared
        );
    }
    let mut ids = HashSet::with_capacity(actual_declared);
    for input in &fixture.inputs {
        if input.id.trim().is_empty() || !ids.insert(input.id.as_str()) {
            bail!(
                "Bloom corpus fixture has an empty or duplicate input id: {:?}",
                input.id
            );
        }
        if input.labels.is_empty()
            || input
                .labels
                .iter()
                .any(|label| label != "F" && label != "X")
            || input.line_start == 0
            || input.line_end < input.line_start
        {
            bail!(
                "Bloom corpus input {} is not a valid CredData F/X line span",
                input.id
            );
        }
    }
    for unavailable in &fixture.unavailable_inputs {
        if unavailable.id.trim().is_empty()
            || unavailable.path.trim().is_empty()
            || unavailable.reason.trim().is_empty()
            || unavailable.category != UNAVAILABLE_SOURCE_FILE_MISSING
            || !ids.insert(unavailable.id.as_str())
        {
            bail!("Bloom corpus fixture has invalid unavailable-input metadata");
        }
    }
    Ok(())
}

fn measure_batch(
    scanner: &CompiledScanner,
    corpus_name: &str,
    chunks: &[Chunk],
    totals: &mut MeasurementTotals,
) -> Result<()> {
    let corpus = scanner.bigram_prefilter_corpus_status(
        corpus_name,
        chunks.iter().map(|chunk| chunk.data.as_bytes()),
    );
    totals.input_count = totals.input_count.saturating_add(corpus.input_count);
    totals.eligible_input_count = totals
        .eligible_input_count
        .saturating_add(corpus.eligible_inputs);
    totals.rejected_input_count = totals
        .rejected_input_count
        .saturating_add(corpus.rejected_inputs);

    scanner.clear_fragment_cache();
    let enabled = scanner
        .scan_chunks_with_backend(chunks, ScanBackend::CpuFallback)
        .context("scan Bloom-enabled corpus batch")?;
    scanner.clear_fragment_cache();
    let bypass = scanner
        .scan_chunks_with_backend_bypassing_bigram_for_diagnostics(chunks, ScanBackend::CpuFallback)
        .context("scan Bloom-bypassed corpus batch")?;
    totals.enabled_findings.extend(finding_identities(enabled));
    totals.bypass_findings.extend(finding_identities(bypass));
    Ok(())
}

fn finding_identities(rows: Vec<Vec<RawMatch>>) -> impl Iterator<Item = FindingIdentity> {
    rows.into_iter().flatten().map(|finding| {
        let span_start = finding.location.offset;
        let span_end = span_start.saturating_add(finding.credential.as_str().len());
        FindingIdentity {
            detector_id: finding.detector_id.to_string(),
            file_path: finding.location.file_path.map(|path| path.to_string()),
            line: finding.location.line,
            span_start,
            span_end,
            credential_sha256: keyhog_core::hex_encode(finding.credential_hash.as_bytes()),
        }
    })
}

fn finding_digest(findings: &[FindingIdentity]) -> String {
    let mut hasher = Sha256::new();
    for finding in findings {
        hash_field(&mut hasher, finding.detector_id.as_bytes());
        match &finding.file_path {
            Some(path) => {
                hash_field(&mut hasher, b"path");
                hash_field(&mut hasher, path.as_bytes());
            }
            None => hash_field(&mut hasher, b"no-path"),
        }
        match finding.line {
            Some(line) => hash_field(&mut hasher, line.to_string().as_bytes()),
            None => hash_field(&mut hasher, b"no-line"),
        }
        hash_field(&mut hasher, finding.span_start.to_string().as_bytes());
        hash_field(&mut hasher, finding.span_end.to_string().as_bytes());
        hash_field(&mut hasher, finding.credential_sha256.as_bytes());
    }
    keyhog_core::hex_encode(hasher.finalize())
}

fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn sha256_hex(bytes: &[u8]) -> String {
    keyhog_core::hex_encode(Sha256::digest(bytes))
}

fn share_basis_points(numerator: u64, denominator: u64) -> u16 {
    if denominator == 0 {
        return 0;
    }
    ((u128::from(numerator) * 10_000) / u128::from(denominator)).min(10_000) as u16
}

fn line_offsets(bytes: &[u8]) -> Vec<usize> {
    let mut offsets = Vec::with_capacity(bytes.len() / 64 + 1);
    offsets.push(0);
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            offsets.push(index + 1);
        }
    }
    offsets
}

fn line_span(
    offsets: &[usize],
    byte_len: usize,
    line_start: usize,
    line_end: usize,
) -> Result<(usize, usize)> {
    let start_index = line_start
        .checked_sub(1)
        .context("line_start must be one-based")?;
    let start = offsets
        .get(start_index)
        .copied()
        .context("line_start exceeds source line count")?;
    if line_end < line_start || line_end > offsets.len() {
        bail!("line_end exceeds source line count");
    }
    let end = if line_end < offsets.len() {
        offsets[line_end]
    } else {
        byte_len
    };
    Ok((start, end))
}

fn safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn prefilter_state_label(state: BigramPrefilterState) -> &'static str {
    match state {
        BigramPrefilterState::Healthy => "healthy",
        BigramPrefilterState::Saturated => "saturated-fail-open",
        BigramPrefilterState::Invalid => "invalid-fail-open",
    }
}

#[cfg(test)]
#[path = "bloom_diagnostic_tests.rs"]
mod tests;
