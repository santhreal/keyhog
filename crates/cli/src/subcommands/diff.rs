//! Compare baseline identities or scan two artifacts and classify removed secrets.

use crate::args::DiffArgs;
use crate::baseline::{Baseline, BaselineEntry};
use crate::exit_codes::EXIT_FINDINGS;
use anyhow::{Context, Result};
use keyhog_core::{DedupScope, DedupedMatch, VerificationResult};
use serde::Serialize;
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::process::ExitCode;

const DEFAULT_MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_VERIFY_TIMEOUT_SECS: u64 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RemovedVerificationState {
    RemovedStillLive,
    RemovedInactive,
    VerificationUnknown,
}

#[derive(Serialize)]
struct RemovedEntry<'a> {
    detector_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_path: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<usize>,
    state: RemovedVerificationState,
}

struct DiffResult<'a> {
    new_entries: Vec<&'a BaselineEntry>,
    removed_entries: Vec<RemovedEntry<'a>>,
    unchanged_entries: Vec<&'a BaselineEntry>,
}

pub(crate) async fn run(args: DiffArgs) -> Result<ExitCode> {
    ensure_regular_input(&args.before, args.artifacts)?;
    ensure_regular_input(&args.after, args.artifacts)?;

    let (before, after, removed_groups) = if args.artifacts {
        scan_artifacts(&args)?
    } else {
        (
            Baseline::load(&args.before)?,
            Baseline::load(&args.after)?,
            HashMap::new(),
        )
    };

    let removed_states = classify_removed(&args, removed_groups).await?;
    let result = compare(&before, &after, &removed_states);

    if args.json {
        print_json(&result, args.hide_unchanged)?;
    } else {
        print_human(&result, args.hide_unchanged);
    }

    if result.new_entries.is_empty() && !has_unsafe_removal(&result) {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(EXIT_FINDINGS))
    }
}

fn ensure_regular_input(path: &Path, artifact_mode: bool) -> Result<()> {
    if path.is_file() {
        return Ok(());
    }
    let kind = if artifact_mode {
        "artifact input"
    } else {
        "baseline file"
    };
    anyhow::bail!(
        "{kind} {} does not exist or is not a regular file",
        path.display()
    );
}

fn scan_artifacts(
    args: &DiffArgs,
) -> Result<(Baseline, Baseline, HashMap<(String, String), DedupedMatch>)> {
    let max_artifact_bytes = args
        .max_artifact_bytes
        .unwrap_or(DEFAULT_MAX_ARTIFACT_BYTES); // LAW10: absent CLI value selects the documented artifact-size default
    if max_artifact_bytes == 0 {
        anyhow::bail!("--max-artifact-bytes must be greater than zero");
    }
    if let Some(detectors) = &args.detectors {
        if !detectors.is_dir() {
            anyhow::bail!(
                "explicit detectors directory {} does not exist or is not a directory",
                detectors.display()
            );
        }
    }
    let requested_detectors = args.detectors.as_deref().unwrap_or(Path::new("detectors")); // LAW10: absent CLI value selects the documented auto-discovery starting path
    let detectors_path = crate::orchestrator_config::auto_discover_detectors(requested_detectors)?;
    let detectors = crate::orchestrator_config::load_detectors_or_embedded(&detectors_path)?;
    let scanner = keyhog_scanner::CompiledScanner::compile_with_gpu_policy(
        detectors,
        keyhog_scanner::GpuInitPolicy::ForceDisabled,
    )
    .with_context(|| {
        format!(
            "compiling detector corpus for artifact diff from {}",
            detectors_path.display()
        )
    })?;

    let before_groups = scan_artifact(&scanner, &args.before, max_artifact_bytes)?;
    scanner.clear_fragment_cache();
    let after_groups = scan_artifact(&scanner, &args.after, max_artifact_bytes)?;
    scanner.clear_fragment_cache();

    let before_findings: Vec<_> = before_groups
        .iter()
        .map(skipped_finding_for_baseline)
        .collect();
    let after_findings: Vec<_> = after_groups
        .iter()
        .map(skipped_finding_for_baseline)
        .collect();
    let before = Baseline::from_findings(&before_findings);
    let after = Baseline::from_findings(&after_findings);
    let after_index = after.index_set();
    let removed_groups = before_groups
        .into_iter()
        .filter_map(|group| {
            let key = group_key(&group);
            (!after_index.contains(&key)).then_some((key, group))
        })
        .collect();
    Ok((before, after, removed_groups))
}

fn read_artifact(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("opening artifact {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("reading artifact metadata for {}", path.display()))?;
    if !metadata.is_file() {
        anyhow::bail!("artifact {} is not a regular file", path.display());
    }
    let length = metadata.len();
    if length > max_bytes {
        anyhow::bail!(
            "artifact {} is {length} bytes, above --max-artifact-bytes {max_bytes}; raise the explicit cap or compare smaller artifacts",
            path.display()
        );
    }
    let read_limit = max_bytes.saturating_add(1);
    let capacity = length.min(max_bytes).min(1024 * 1024) as usize;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading artifact {}", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        anyhow::bail!(
            "artifact {} grew beyond --max-artifact-bytes {max_bytes} while it was read; retry a stable file or raise the explicit cap",
            path.display()
        );
    }
    Ok(bytes)
}

fn scan_artifact(
    scanner: &keyhog_scanner::CompiledScanner,
    path: &Path,
    max_bytes: u64,
) -> Result<Vec<DedupedMatch>> {
    let bytes = read_artifact(path, max_bytes)?;
    let text = String::from_utf8(bytes).with_context(|| {
        format!(
            "artifact {} is not UTF-8 text; use `keyhog scan --binary` for binary inputs",
            path.display()
        )
    })?;
    let size_bytes = text.len() as u64;
    let chunk = keyhog_core::Chunk {
        data: text.into(),
        metadata: keyhog_core::ChunkMetadata {
            source_type: "diff-artifact".into(),
            path: Some(path.to_string_lossy().into_owned().into()),
            size_bytes: Some(size_bytes),
            ..Default::default()
        },
    };
    let matches = scanner.scan_with_backend(&chunk, keyhog_scanner::ScanBackend::CpuFallback);
    Ok(keyhog_core::dedup_cross_detector(
        keyhog_core::dedup_matches(matches, &DedupScope::Credential),
    ))
}

fn skipped_finding_for_baseline(group: &DedupedMatch) -> keyhog_core::VerifiedFinding {
    keyhog_core::VerifiedFinding {
        detector_id: group.detector_id.clone(),
        detector_name: group.detector_name.clone(),
        service: group.service.clone(),
        severity: group.severity,
        credential_redacted: keyhog_core::redact(&group.credential),
        credential_hash: group.credential_hash,
        location: group.primary_location.clone(),
        additional_locations: group.additional_locations.clone(),
        verification: VerificationResult::Skipped,
        metadata: HashMap::new(),
        confidence: group.confidence,
    }
}

fn group_key(group: &DedupedMatch) -> (String, String) {
    (
        group.detector_id.to_string(),
        format!("sha256:{}", keyhog_core::hex_encode(&group.credential_hash)),
    )
}

async fn classify_removed(
    args: &DiffArgs,
    removed_groups: HashMap<(String, String), DedupedMatch>,
) -> Result<HashMap<(String, String), RemovedVerificationState>> {
    if !args.verify_removed {
        return Ok(HashMap::new());
    }
    let verify_timeout = args.verify_timeout.unwrap_or(DEFAULT_VERIFY_TIMEOUT_SECS); // LAW10: absent CLI value selects the documented verification timeout
    if verify_timeout == 0 {
        anyhow::bail!("--verify-timeout must be greater than zero");
    }

    #[cfg(not(feature = "verify"))]
    {
        drop(removed_groups);
        anyhow::bail!("--verify-removed requires a keyhog build with the `verify` feature");
    }

    #[cfg(feature = "verify")]
    {
        if removed_groups.is_empty() {
            return Ok(HashMap::new());
        }
        let requested_detectors = args.detectors.as_deref().unwrap_or(Path::new("detectors")); // LAW10: absent CLI value selects the documented auto-discovery starting path
        let detectors_path =
            crate::orchestrator_config::auto_discover_detectors(requested_detectors)?;
        let detectors = crate::orchestrator_config::load_detectors_or_embedded(&detectors_path)?;
        let verifier = keyhog_verifier::VerificationEngine::new(
            &detectors,
            keyhog_verifier::VerifyConfig {
                timeout: std::time::Duration::from_secs(verify_timeout),
                ..Default::default()
            },
        )
        .context("initializing removed-secret verification")?;
        let mut verify_candidates: Vec<_> = removed_groups.into_iter().collect();
        verify_candidates.sort_by(|(left, _), (right, _)| left.cmp(right));
        let findings = verifier
            .verify_all(
                verify_candidates
                    .into_iter()
                    .map(|(_, finding)| finding)
                    .collect(),
            )
            .await;
        Ok(findings
            .into_iter()
            .map(|finding| {
                let key = (
                    finding.detector_id.to_string(),
                    format!(
                        "sha256:{}",
                        keyhog_core::hex_encode(&finding.credential_hash)
                    ),
                );
                (key, removed_state(&finding.verification))
            })
            .collect())
    }
}

pub(crate) fn removed_state(result: &VerificationResult) -> RemovedVerificationState {
    match result {
        VerificationResult::Live => RemovedVerificationState::RemovedStillLive,
        VerificationResult::Dead | VerificationResult::Revoked => {
            RemovedVerificationState::RemovedInactive
        }
        VerificationResult::RateLimited
        | VerificationResult::Error(_)
        | VerificationResult::Unverifiable
        | VerificationResult::Skipped => RemovedVerificationState::VerificationUnknown,
    }
}

fn compare<'a>(
    before: &'a Baseline,
    after: &'a Baseline,
    removed_states: &HashMap<(String, String), RemovedVerificationState>,
) -> DiffResult<'a> {
    let before_index = before.index_set();
    let after_index = after.index_set();
    let mut new_entries: Vec<_> = after
        .entries
        .iter()
        .filter(|entry| !before_index.contains(&entry_key(entry)))
        .collect();
    let mut removed_entries: Vec<_> = before
        .entries
        .iter()
        .filter(|entry| !after_index.contains(&entry_key(entry)))
        .map(|entry| RemovedEntry {
            detector_id: &entry.detector_id,
            file_path: entry.file_path.as_deref(),
            line: entry.line,
            state: removed_states
                .get(&entry_key(entry))
                .copied()
                .unwrap_or(RemovedVerificationState::VerificationUnknown), // LAW10: missing verification evidence is the fail-closed state and blocks success
        })
        .collect();
    let mut unchanged_entries: Vec<_> = after
        .entries
        .iter()
        .filter(|entry| before_index.contains(&entry_key(entry)))
        .collect();
    new_entries.sort_by(|a, b| a.detector_id.cmp(&b.detector_id));
    removed_entries.sort_by(|a, b| a.detector_id.cmp(b.detector_id));
    unchanged_entries.sort_by(|a, b| a.detector_id.cmp(&b.detector_id));
    DiffResult {
        new_entries,
        removed_entries,
        unchanged_entries,
    }
}

fn entry_key(entry: &BaselineEntry) -> (String, String) {
    (entry.detector_id.clone(), entry.credential_hash.clone())
}

fn has_unsafe_removal(result: &DiffResult<'_>) -> bool {
    result
        .removed_entries
        .iter()
        .any(|entry| removed_state_blocks_success(entry.state))
}

fn removed_state_blocks_success(state: RemovedVerificationState) -> bool {
    state != RemovedVerificationState::RemovedInactive
}

fn print_json(result: &DiffResult<'_>, hide_unchanged: bool) -> Result<()> {
    let inactive = result
        .removed_entries
        .iter()
        .filter(|entry| entry.state == RemovedVerificationState::RemovedInactive)
        .count();
    let still_live = result
        .removed_entries
        .iter()
        .filter(|entry| entry.state == RemovedVerificationState::RemovedStillLive)
        .count();
    let unknown = result.removed_entries.len() - inactive - still_live;
    let payload = serde_json::json!({
        "new": result.new_entries,
        "removed": result.removed_entries,
        "unchanged": if hide_unchanged { serde_json::Value::Null } else { serde_json::to_value(&result.unchanged_entries)? },
        "summary": {
            "new": result.new_entries.len(),
            "removed": result.removed_entries.len(),
            "unchanged": result.unchanged_entries.len(),
            "new_count": result.new_entries.len(),
            "removed_count": result.removed_entries.len(),
            "removed_still_live_count": still_live,
            "removed_inactive_count": inactive,
            "verification_unknown_count": unknown,
            "unchanged_count": result.unchanged_entries.len(),
        }
    });
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}

fn print_human(result: &DiffResult<'_>, hide_unchanged: bool) {
    let palette = crate::style::for_stdout();
    let paint = |color: &str, text: String| format!("{color}{text}{}", palette.reset);
    let unsafe_removal = has_unsafe_removal(result);
    let new_summary = if result.new_entries.is_empty() {
        paint(palette.green, "PASS 0 new".into())
    } else {
        paint(
            palette.red,
            format!("FAIL {} new", result.new_entries.len()),
        )
    };
    let removed_summary = if unsafe_removal {
        paint(
            palette.yellow,
            format!("RISK {} removed", result.removed_entries.len()),
        )
    } else {
        paint(
            palette.green,
            format!("PASS {} removed", result.removed_entries.len()),
        )
    };
    println!("keyhog diff\n");
    println!(
        "  {}   {}   {}\n",
        new_summary,
        removed_summary,
        paint(
            palette.dim,
            format!("= {} unchanged", result.unchanged_entries.len())
        ),
    );
    for entry in &result.new_entries {
        println!(
            "{} {} @ {}{}",
            paint(palette.red, "NEW".into()),
            entry.detector_id,
            entry.file_path.as_deref().unwrap_or("<unknown>"), // LAW10: display-only location label; the finding and exit status are unchanged
            entry
                .line
                .map(|line| format!(":{line}"))
                .unwrap_or_default() // LAW10: display-only absent line suffix; the finding and exit status are unchanged
        );
    }
    for entry in &result.removed_entries {
        let state_color = match entry.state {
            RemovedVerificationState::RemovedStillLive => palette.red,
            RemovedVerificationState::RemovedInactive => palette.green,
            RemovedVerificationState::VerificationUnknown => palette.yellow,
        };
        println!(
            "{} {} {} @ {}{}",
            paint(palette.yellow, "REMOVED".into()),
            paint(state_color, removed_state_label(entry.state).into()),
            entry.detector_id,
            entry.file_path.unwrap_or("<unknown>"), // LAW10: display-only location label; the finding and exit status are unchanged
            entry
                .line
                .map(|line| format!(":{line}"))
                .unwrap_or_default() // LAW10: display-only absent line suffix; the finding and exit status are unchanged
        );
    }
    if !hide_unchanged {
        for entry in &result.unchanged_entries {
            println!(
                "{} {} @ {}{}",
                paint(palette.dim, "UNCHANGED".into()),
                entry.detector_id,
                entry.file_path.as_deref().unwrap_or("<unknown>"), // LAW10: display-only location label; the finding and exit status are unchanged
                entry
                    .line
                    .map(|line| format!(":{line}"))
                    .unwrap_or_default() // LAW10: display-only absent line suffix; the finding and exit status are unchanged
            );
        }
    }
    if result.new_entries.is_empty() && !unsafe_removal {
        println!(
            "{}",
            paint(
                palette.green,
                "PASS no new or unverified live-risk findings".into()
            )
        );
    } else {
        println!(
            "{}",
            paint(
                palette.red,
                "FAIL new, live, or verification-unknown findings remain".into()
            )
        );
    }
}

#[doc(hidden)]
pub(crate) fn removed_state_label_for_test(result: &VerificationResult) -> &'static str {
    removed_state_label(removed_state(result))
}

#[doc(hidden)]
pub(crate) fn removed_result_blocks_success_for_test(result: &VerificationResult) -> bool {
    removed_state_blocks_success(removed_state(result))
}

fn removed_state_label(state: RemovedVerificationState) -> &'static str {
    match state {
        RemovedVerificationState::RemovedStillLive => "removed_still_live",
        RemovedVerificationState::RemovedInactive => "removed_inactive",
        RemovedVerificationState::VerificationUnknown => "verification_unknown",
    }
}
