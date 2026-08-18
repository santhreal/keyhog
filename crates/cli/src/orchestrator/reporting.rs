//! Scan completion reporting hooks (progress ticker, summaries, dogfood trace).

use keyhog_core::{Severity, VerifiedFinding};
use std::io::Write;

use crate::style::terminal_palette;
// keyhog brand yellow (#ffd60a), severity heat colours and a dimmed rail, as
// 24-bit truecolor SGR. The escape literals live in `crate::style` (the one CLI
// file exempt from the no-raw-ANSI gate); imported here under the local `C_*`
// names the summary renderers use. Gated behind the caller's `color` flag
// (TTY && !NO_COLOR) so piped/`NO_COLOR` output stays plain.
use crate::style::{
    SEV_AMBER as C_AMBER, SEV_BRAND as C_BRAND, SEV_CRITICAL as C_CRITICAL, SEV_HIGH as C_HIGH,
    SEV_LOW as C_LOW, SEV_MEDIUM as C_MEDIUM, SEV_MUTED as C_MUTED, SEV_RESET as C_RESET,
    SEV_SAFE as C_SAFE,
};

mod progress;
pub(crate) use progress::{
    fmt_secs, progress_ticker, render_progress_bar, render_reporting_ticker_line,
    render_ticker_line, render_verification_ticker_line, reporting_ticker, TickerGuard,
};
// `verification_ticker` only exists on a build that can verify, so the import
// must carry the same gate as the item. An unconditional import broke every
// feature set without `verify`, including `--features ci`.
#[cfg(feature = "verify")]
pub(crate) use progress::verification_ticker;
#[cfg(test)]
pub(crate) use progress::{BAR_WIDTH, FRAMES};

/// Emit one redacted `[stream]` preview line per REPORTED finding.
///
/// Wired to the resolved `VerifiedFinding` stream, the same findings the
/// authoritative report and the exit code are computed from. NOT the raw
/// scanner matches. The previous wiring previewed every `RawMatch` as it left
/// the scanner thread, BEFORE the confidence floor / `--min-confidence` and
/// the test-fixture suppression that govern the report, so a streamed
/// `[stream] CRITICAL …` line could announce a "leak" the report then dropped
/// (and the tool exited 0). A streamed line now strictly implies a reported
/// finding: stream count == report count.
pub(crate) fn stream_finding_preview<W: Write>(w: &mut W, f: &VerifiedFinding) {
    let path = f.location.file_path.as_deref().unwrap_or("<stdin>"); // LAW10: absent path/field => display placeholder for REPORTING only; finding still emitted, recall-safe
    let line = f
        .location
        .line
        .map(|n| n.to_string())
        .unwrap_or_else(|| "?".into()); // LAW10: absent name/label => display default; reporting-only, recall-safe
    if let Err(error) = writeln!(
        w,
        "[stream] {sev:<8} {service}/{detector}  {path}:{line}  {redacted}",
        // Canonical severity text (kebab-case), uppercased for the preview.
        // Deriving from `{:?}` here diverged for `ClientSafe` (Debug =>
        // "CLIENTSAFE", not "CLIENT-SAFE"); route through the one table.
        sev = f.severity.as_str().to_uppercase(),
        service = f.service,
        detector = f.detector_id,
        path = path,
        line = line,
        redacted = f.credential_redacted,
    ) {
        tracing::debug!(%error, "stream finding preview write error");
    }
}

/// Stream a `[stream]` preview line for every reported finding. Called from the
/// run loop after `filter_and_resolve` / `finalize` / suppression / baseline
/// filtering, so the stream is consistent with the report and the exit code.
pub(crate) fn stream_report_previews(findings: &[VerifiedFinding]) {
    if findings.is_empty() {
        return;
    }
    let mut w = std::io::LineWriter::new(std::io::stderr());
    for f in findings {
        stream_finding_preview(&mut w, f);
    }
    let _ = w.flush(); // LAW10: unused-binding marker; no runtime effect, not a fallback
}

/// The unmissable "scan did not finish" notice, or `None` when the scanner
/// thread ran to completion. Pure (takes the flag) so it is unit-testable; the
/// completion summary feeds it `SCANNER_PANICKED`.
///
/// Law 10: a scanner-thread panic at `dispatch.rs` returns the partial findings
/// gathered so far AND sets `SCANNER_PANICKED` + a dedicated `EXIT_SCANNER_PANIC`
/// exit code, but the only terminal output was a `tracing::error!`: filtered
/// out at the default verbosity, exactly like the `tracing::debug!` drops this
/// sweep replaced. So a crashed scan still printed "Scan complete. Found 0
/// secrets" as its last word and read as a clean tree. This surfaces the crash
/// unconditionally on stderr so "0 secrets" can never be mistaken for clean.
pub(crate) fn scanner_panic_notice(panicked: bool) -> Option<String> {
    panicked.then(|| {
        "SCAN INCOMPLETE: the scanner thread panicked mid-scan. The findings below \
         are PARTIAL: chunks in flight when it crashed were NOT scanned, so a \
         \"0 secrets\" / low count is NOT a clean result. The process exits with a \
         distinct scanner-panic code. Re-run; if it persists, file a bug with the \
         input that triggered it."
            .to_string()
    })
}

/// Per-finding verification outcome tally for the completion line. Mirrors the
/// HTML report's verification honesty in the terminal: a "Found N secrets" line
/// must never imply those N are confirmed-live when verification was skipped or
/// no verifier exists. Categories are mutually exclusive and sum to the finding
/// count.
#[derive(Default, Debug, PartialEq, Eq)]
pub(crate) struct VerificationBreakdown {
    /// `Live`: the credential was confirmed active against its service.
    pub live: usize,
    /// `Revoked` + `Dead`: verified, but not currently active.
    pub inactive: usize,
    /// `Skipped`: verification was not attempted (no `--verify` / verifier off).
    pub skipped: usize,
    /// `Unverifiable`: no verifier exists for this credential type.
    pub unverifiable: usize,
    /// `RateLimited` + `Error`: a check ran but could not conclude.
    pub incomplete: usize,
}

/// Tally findings by verification outcome. Pure (testable); the exhaustive match
/// means a new `VerificationResult` variant fails to compile rather than being
/// silently miscounted (Law 10).
pub(crate) fn verification_breakdown(findings: &[VerifiedFinding]) -> VerificationBreakdown {
    use keyhog_core::VerificationResult as V;
    let mut b = VerificationBreakdown::default();
    for f in findings {
        match &f.verification {
            V::Live => b.live += 1,
            V::Revoked | V::Dead => b.inactive += 1,
            V::Skipped => b.skipped += 1,
            V::Unverifiable => b.unverifiable += 1,
            V::RateLimited | V::Error(_) => b.incomplete += 1,
        }
    }
    b
}

fn count_token(count: usize, label: &str, color_code: &str, color: bool) -> String {
    crate::style::paint(format!("{count} {label}"), color_code, color)
}

/// Singular/plural noun for a secret count. One owner so the completion summary
/// and the verification ticker agree; a single finding must read "1 secret".
pub(super) fn secret_noun(count: usize) -> &'static str {
    if count == 1 {
        "secret"
    } else {
        "secrets"
    }
}

/// Singular/plural noun for a finding count (scan/reporting tickers).
pub(super) fn finding_noun(count: usize) -> &'static str {
    if count == 1 {
        "finding"
    } else {
        "findings"
    }
}

pub(super) fn dot_join(parts: &[String], color: bool) -> String {
    let sep = if color {
        format!("{C_MUTED} · {C_RESET}")
    } else {
        " · ".to_string()
    };
    parts.join(&sep)
}

fn severity_color(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => C_CRITICAL,
        Severity::High => C_HIGH,
        Severity::Medium => C_MEDIUM,
        Severity::Low => C_LOW,
        Severity::ClientSafe => C_SAFE,
        Severity::Info => C_MUTED,
    }
}

pub(crate) fn render_severity_line(findings: &[VerifiedFinding], color: bool) -> Option<String> {
    if findings.is_empty() {
        return None;
    }
    let mut critical = 0usize;
    let mut high = 0usize;
    let mut medium = 0usize;
    let mut low = 0usize;
    let mut client_safe = 0usize;
    let mut info = 0usize;
    for finding in findings {
        match finding.severity {
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
            Severity::ClientSafe => client_safe += 1,
            Severity::Info => info += 1,
        }
    }
    let counts = [
        (Severity::Critical, critical),
        (Severity::High, high),
        (Severity::Medium, medium),
        (Severity::Low, low),
        (Severity::ClientSafe, client_safe),
        (Severity::Info, info),
    ];
    let parts: Vec<String> = counts
        .into_iter()
        .filter(|(_, count)| *count > 0)
        .map(|(severity, count)| {
            count_token(count, severity.as_str(), severity_color(severity), color)
        })
        .collect();
    let (muted, reset) = if color { (C_MUTED, C_RESET) } else { ("", "") };
    Some(format!(
        "{muted}↳ severity: {reset}{}",
        dot_join(&parts, color)
    ))
}

/// Render the honesty sub-line under "Found N secrets". `None` when there are no
/// findings (nothing to verify). When NOTHING was actually checked (everything
/// `Skipped`), it states plainly that verification was not run and points at
/// `--verify`, so "N secrets" is never mistaken for "N live secrets".
pub(crate) fn render_verification_line(
    b: &VerificationBreakdown,
    total: usize,
    color: bool,
) -> Option<String> {
    if total == 0 {
        return None;
    }
    let (muted, brand, amber, reset) = if color {
        (C_MUTED, C_BRAND, C_AMBER, C_RESET)
    } else {
        ("", "", "", "")
    };
    // Verification was never attempted for ANY finding: say so explicitly.
    if b.skipped == total {
        return Some(format!(
            "{muted}↳ verification: {amber}not checked{reset}{muted}: liveness check did not run; pass {brand}--verify{reset}{muted} \
             to confirm which are active{reset}"
        ));
    }
    let mut parts: Vec<String> = Vec::new();
    if b.live > 0 {
        parts.push(count_token(b.live, "live", C_CRITICAL, color));
    }
    if b.inactive > 0 {
        parts.push(count_token(b.inactive, "revoked/dead", C_SAFE, color));
    }
    if b.skipped > 0 {
        parts.push(count_token(b.skipped, "not checked", C_AMBER, color));
    }
    if b.unverifiable > 0 {
        parts.push(count_token(b.unverifiable, "no verifier", C_AMBER, color));
    }
    if b.incomplete > 0 {
        parts.push(count_token(b.incomplete, "inconclusive", C_AMBER, color));
    }
    Some(format!(
        "{muted}↳ verification: {reset}{}",
        dot_join(&parts, color)
    ))
}

pub(crate) fn report_completion_summary(
    findings: &[VerifiedFinding],
    elapsed: f64,
    ansi: bool,
    backend_override: Option<keyhog_scanner::ScanBackend>,
) {
    let count = findings.len();
    let palette = terminal_palette(ansi, false);
    let completion =
        if crate::BACKEND_RECOVERY_EVENTS.load(std::sync::atomic::Ordering::Relaxed) > 0 {
            "Scan complete after recovery."
        } else {
            "Scan complete."
        };
    // Surface a mid-scan crash FIRST, before the "Scan complete!" line, so the
    // incompleteness frames everything below it (Law 10).
    if let Some(notice) =
        scanner_panic_notice(crate::SCANNER_PANICKED.load(std::sync::atomic::Ordering::Relaxed))
    {
        eprintln!("{}FAIL{} {notice}", palette.red, palette.reset);
    }
    if count == 0 {
        eprintln!(
            "\n{completion} Found {}0{} secrets in {}{:.2}s{}.",
            palette.green, palette.reset, palette.yellow, elapsed, palette.reset
        );
    } else {
        // Pluralize the noun so a single finding reads "Found 1 secret", not
        // "1 secrets"; matches the stdout `Results` footer's `secret{plural}`.
        let noun = secret_noun(count);
        eprintln!(
            "\n{completion} Found {}{}{} {} in {}{:.2}s{}.",
            palette.red, count, palette.reset, noun, palette.yellow, elapsed, palette.reset
        );
        if let Some(line) = render_severity_line(findings, ansi) {
            eprintln!("{line}");
        }
        // Honesty sub-line: how many of those N are confirmed live vs unchecked.
        if let Some(line) = render_verification_line(&verification_breakdown(findings), count, ansi)
        {
            eprintln!("{line}");
        }
    }
    report_skip_summary(ansi);
    report_backend_summary(ansi, backend_override);
}

/// Surface which backend selection ACTUALLY used this scan, and, when a GPU is
/// present but did not engage. WHY.
///
/// The per-batch routing decision was previously logged only at
/// `tracing::debug!` (target `keyhog::routing`), invisible at the default
/// `keyhog=warn` verbosity. This prints one completion line stating whether
/// calibrated GPU and non-GPU routes ran. Exact per-bucket route identity stays
/// in the persisted autoroute decision rather than being guessed from aggregate
/// chunk counters.
pub(crate) fn report_backend_summary(
    ansi: bool,
    backend_override: Option<keyhog_scanner::ScanBackend>,
) {
    use std::sync::atomic::Ordering;
    let total = crate::SCANNED_CHUNKS.load(Ordering::Relaxed);
    if total == 0 {
        // Nothing was scanned (empty tree, source error, zero chunks), there is
        // no routing decision to report.
        return;
    }
    // GPU_SCANNED_CHUNKS counts the chunks the coalesced GPU arm dispatched to
    // GPU region presence; everything else (the default fused CPU path and the
    // coalesced SIMD arm) ran on SIMD/CPU.
    let gpu = crate::GPU_SCANNED_CHUNKS.load(Ordering::Relaxed).min(total);
    let non_gpu = total - gpu;
    let recovery_events = crate::BACKEND_RECOVERY_EVENTS.load(Ordering::Relaxed);
    let recovered_chunks = crate::BACKEND_RECOVERED_CHUNKS.load(Ordering::Relaxed);
    let recovered_bytes = crate::BACKEND_RECOVERED_BYTES.load(Ordering::Relaxed);
    let hw = keyhog_scanner::hw_probe::probe_hardware();
    let line = if let Some(backend) = backend_override {
        format!("backend: {} (forced via --backend)", backend.label())
    } else if recovery_events > 0 {
        format!(
            "backend: an automatic route faulted and completed through exact recovery; recovered {recovered_chunks} chunk(s), {recovered_bytes} byte(s) across {recovery_events} event(s); scan coverage is complete; repair: keyhog calibrate-autoroute"
        )
    } else if gpu > 0 && non_gpu > 0 {
        format!(
            "backend: calibrated GPU route ({gpu} chunk(s)) + calibrated non-GPU route ({non_gpu} chunk(s)); inspect `keyhog backend --autoroute` for exact per-bucket routes"
        )
    } else if gpu > 0 {
        "backend: calibrated GPU driver peer (inspect `keyhog backend --autoroute` for the exact route)".to_string()
    } else if hw.gpu_available && !hw.gpu_is_software {
        let name = hw.gpu_name.as_deref().unwrap_or("a GPU").trim().to_string(); // LAW10: absent name/label => display default; reporting-only, recall-safe
        format!(
            "backend: calibrated non-GPU route; {name} was eligible but was not the \
             fastest measured-correct route for the exact workload bucket(s) scanned. \
             Inspect the persisted decision with `keyhog backend --autoroute`; explicit \
             `--backend gpu-cuda` or `--backend gpu-wgpu` is diagnostic only."
        )
    } else {
        "backend: calibrated non-GPU route (no hardware GPU available on this host)".to_string()
    };

    let palette = terminal_palette(ansi, false);
    eprintln!("{}INFO{} {line}", palette.cyan, palette.reset);
}

/// Report what the persisted autoroute decision cache actually did.
///
/// The `backend:` line says which route ran. It cannot say whether that route
/// came from persisted evidence or from a recovery, how many batches asked, or
/// why the ones that missed missed. Without those an operator cannot tell a
/// cache that is earning its keep from one that is dead weight, and a key that
/// misses on every single run looks exactly like a corpus that was never
/// calibrated.
///
/// Misses additionally name every distinct uncalibrated bucket at `info`, so
/// ONE recalibration can be planned to cover all of them. Announcing only the
/// first missing bucket, which is all the recovery warning can do, turns a
/// corpus with N uncalibrated buckets into N repair cycles.
///
/// This is called outside the progress-gated completion summary, alongside
/// [`report_skip_summary`], because routing state is status rather than
/// decoration. `--format json -o <file>` suppresses the completion summary
/// entirely, and that is precisely the invocation CI and calibration harnesses
/// use, so gating this behind it would hide the cache rate from every
/// non-interactive run.
pub(crate) fn report_autoroute_cache_summary(ansi: bool, backend_forced: bool) {
    if backend_forced {
        // An explicit `--backend` bypasses automatic routing, so the cache was
        // never consulted and any rate would describe a different scan.
        return;
    }
    let stats = crate::orchestrator::dispatch::autoroute_cache_stats();
    let Some(summary) = crate::orchestrator::dispatch::render_cache_summary(&stats) else {
        return;
    };
    let palette = terminal_palette(ansi, false);
    let label = if stats.misses > 0 {
        format!("{}WARN{}", palette.yellow, palette.reset)
    } else {
        format!("{}INFO{}", palette.cyan, palette.reset)
    };
    eprintln!("{label} {summary}");
    for bucket in crate::orchestrator::dispatch::render_missing_buckets(&stats) {
        tracing::info!(
            target: "keyhog::routing",
            "uncalibrated autoroute bucket, {bucket}"
        );
    }
}

/// Report scanner materialization (mapped from execution pack vs compiled in process).
pub(crate) fn report_scanner_materialization_summary(
    ansi: bool,
    materialization: Option<&crate::orchestrator::ScannerMaterialization>,
) {
    let palette = terminal_palette(ansi, false);
    let line = match materialization {
        Some(crate::orchestrator::ScannerMaterialization::MappedPack { generation }) => {
            format!("scanner: mapped from execution pack {generation}")
        }
        Some(crate::orchestrator::ScannerMaterialization::Compiled { matcher_outcome }) => {
            format!("scanner: compiled in process (matcher-artifact: {})", matcher_outcome.as_str())
        }
        None => "scanner: materialization unknown".to_string(),
    };
    eprintln!("{}INFO{} {line}", palette.cyan, palette.reset);
}

/// Report cache status and entry counts for every registered cache kind.
pub(crate) fn report_compiled_cache_summary(
    ansi: bool,
    orchestrator: &crate::orchestrator::ScanOrchestrator,
) {
    let palette = terminal_palette(ansi, false);
    let cache_base = dirs::cache_dir();
    for kind in keyhog_core::CacheKind::ALL {
        let (state, entry_count) = match kind {
            keyhog_core::CacheKind::HyperscanShards => {
                let dir = orchestrator.effective_config.hyperscan_cache_dir.clone()
                    .or_else(|| cache_base.as_ref().map(|b| b.join("keyhog")));
                let count = dir.as_deref().map_or(0, |d| keyhog_scanner::cache_eviction::count_matching_entries(d, *kind));
                let state = if orchestrator.effective_config.hyperscan_cache_dir.is_none() && cache_base.is_none() {
                    "unusable"
                } else if count > 0 {
                    "hit"
                } else {
                    "miss"
                };
                (state, count)
            }
            keyhog_core::CacheKind::MatcherArtifacts => {
                let dir = keyhog_scanner::configured_matcher_artifact_cache_dir()
                    .or_else(|| cache_base.as_ref().map(|b| b.join(keyhog_core::KEYHOG_MATCHER_ARTIFACTS_SUBDIR)));
                let count = dir.as_deref().map_or(0, |d| keyhog_scanner::cache_eviction::count_matching_entries(d, *kind));
                let state = match &orchestrator.scanner_materialization {
                    Some(crate::orchestrator::ScannerMaterialization::Compiled { matcher_outcome }) => matcher_outcome.as_str(),
                    Some(crate::orchestrator::ScannerMaterialization::MappedPack { .. }) => "disabled",
                    None => "disabled",
                };
                (state, count)
            }
            keyhog_core::CacheKind::GpuPrograms => {
                let dir = cache_base.as_ref().map(|b| b.join("keyhog").join("programs"));
                let count = dir.as_deref().map_or(0, |d| keyhog_scanner::cache_eviction::count_matching_entries(d, *kind));
                let state = if count > 0 { "hit" } else { "compiled" };
                (state, count)
            }
            keyhog_core::CacheKind::DetectorPlans => {
                ("compiled", 0)
            }
            keyhog_core::CacheKind::LockFiles => {
                let dir = cache_base.as_ref().map(|b| b.join("keyhog"));
                let count = dir.as_deref().map_or(0, |d| keyhog_scanner::cache_eviction::count_matching_entries(d, *kind));
                ("active", count)
            }
        };
        eprintln!(
            "{}INFO{} cache {}: {} ({} entries)",
            palette.cyan,
            palette.reset,
            kind.label(),
            state,
            entry_count
        );
    }
}

pub(crate) fn report_skip_summary(ansi: bool) {
    // Snapshot every coverage-gap counter once, then render each non-zero
    // category from the ONE canonical set this human summary and the structured
    // SARIF/HTML report share (`crate::reporting::CoverageGapKind`). A category
    // can therefore never appear on one surface and not the other, a gap
    // visible on the terminal but absent from SARIF would be a structured
    // false-clean (Law 10). Adding a category is a compile error until both
    // surfaces handle it.
    use crate::reporting::{CoverageCounts, CoverageGapKind, CoverageSeverity};
    let counts = CoverageCounts::current();
    for kind in CoverageGapKind::ALL {
        let n = kind.count(&counts);
        if n == 0 {
            continue;
        }
        // `Fail` (red) = these bytes were genuinely NOT covered, so a "no secrets
        // found" result is not a clean bill of health. `Warn` (yellow) = a
        // deliberate skip (size cap, binary, exclusion) or a partial
        // decode-through the raw scan still covered.
        let palette = terminal_palette(ansi, false);
        let (label, color) = match kind.severity() {
            CoverageSeverity::Fail => ("FAIL", palette.red),
            CoverageSeverity::Warn => ("WARN", palette.yellow),
        };
        let msg = kind.human_reason(n);
        eprintln!("{color}{label} {msg}{}", palette.reset);
    }
}

/// Dump the captured dogfood events as a single JSON object on stderr.
pub(crate) fn dump_dogfood_trace() {
    if !keyhog_scanner::telemetry::is_dogfood_enabled() {
        return;
    }
    let events = keyhog_scanner::telemetry::drain_events();
    let suppressed = keyhog_scanner::telemetry::example_suppression_count();
    let static_recovery_rejections = keyhog_scanner::telemetry::static_recovery_rejection_counts();
    let detail_events_dropped = keyhog_scanner::telemetry::dogfood_detail_events_dropped();
    let payload = serde_json::json!({
        "dogfood": {
            "example_suppressions_total": suppressed,
            "static_recovery_rejections": static_recovery_rejections,
            "detail_events_dropped": detail_events_dropped,
            "events": events,
        }
    });
    eprintln!("{payload}");
}

#[cfg(test)]
mod tests;
