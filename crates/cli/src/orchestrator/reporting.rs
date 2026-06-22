//! Scan completion reporting hooks (progress ticker, summaries, dogfood trace).

use keyhog_core::VerifiedFinding;
use std::io::Write;
use std::sync::Arc;
use std::time::Instant;

use crate::style::{terminal_clear_line_prefix, terminal_palette};

/// Emit one redacted `[stream]` preview line per REPORTED finding.
///
/// Wired to the resolved `VerifiedFinding` stream — the same findings the
/// authoritative report and the exit code are computed from — NOT the raw
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
        sev = format!("{:?}", f.severity).to_uppercase(),
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
/// exit code, but the only terminal output was a `tracing::error!` — filtered
/// out at the default verbosity, exactly like the `tracing::debug!` drops this
/// sweep replaced. So a crashed scan still printed "Scan complete. Found 0
/// secrets" as its last word and read as a clean tree. This surfaces the crash
/// unconditionally on stderr so "0 secrets" can never be mistaken for clean.
pub(crate) fn scanner_panic_notice(panicked: bool) -> Option<String> {
    panicked.then(|| {
        "SCAN INCOMPLETE: the scanner thread panicked mid-scan. The findings below \
         are PARTIAL — chunks in flight when it crashed were NOT scanned, so a \
         \"0 secrets\" / low count is NOT a clean result. The process exits with a \
         distinct scanner-panic code. Re-run; if it persists, file a bug with the \
         input that triggered it."
            .to_string()
    })
}

pub(crate) fn report_completion_summary(
    count: usize,
    elapsed: f64,
    ansi: bool,
    backend_override: Option<keyhog_scanner::ScanBackend>,
) {
    let palette = terminal_palette(ansi, false);
    // Surface a mid-scan crash FIRST, before the "Scan complete!" line, so the
    // incompleteness frames everything below it (Law 10).
    if let Some(notice) =
        scanner_panic_notice(crate::SCANNER_PANICKED.load(std::sync::atomic::Ordering::Relaxed))
    {
        eprintln!("{}FAIL{} {notice}", palette.red, palette.reset);
    }
    if count == 0 {
        eprintln!(
            "\nScan complete. Found {}0{} secrets in {}{:.2}s{}.",
            palette.green, palette.reset, palette.yellow, elapsed, palette.reset
        );
    } else {
        eprintln!(
            "\nScan complete. Found {}{}{} secrets in {}{:.2}s{}.",
            palette.red, count, palette.reset, palette.yellow, elapsed, palette.reset
        );
    }
    report_skip_summary(ansi);
    report_backend_summary(ansi, backend_override);
}

/// Surface which backend selection ACTUALLY used this scan, and — when a GPU is
/// present but did not engage — WHY.
///
/// The per-batch routing decision was previously logged only at
/// `tracing::debug!` (target `keyhog::routing`), invisible at the default
/// `keyhog=warn` verbosity. So a scan that CORRECTLY chose SIMD — which is
/// measured faster than the current GPU region-presence route for keyhog's
/// detector set through the measured sweep (host fold/coalesce, dispatch,
/// readback, and the shared CPU phase-2 tail; see
/// `measure_fastest_correct_backend`) — read to the operator as "GPU backend
/// selection is broken." This prints ONE
/// completion line stating the backend(s) used and the routing rationale, so the
/// decision is visible instead of buried (Law 10 / coherence). Reuses the
/// scanner's existing per-chunk telemetry (`gpu_dispatches` vs `files_scanned`);
/// no new counters.
pub(crate) fn report_backend_summary(
    ansi: bool,
    backend_override: Option<keyhog_scanner::ScanBackend>,
) {
    use std::sync::atomic::Ordering;
    let total = crate::SCANNED_CHUNKS.load(Ordering::Relaxed);
    if total == 0 {
        // Nothing was scanned (empty tree, source error, zero chunks) — there is
        // no routing decision to report.
        return;
    }
    // GPU_SCANNED_CHUNKS counts the chunks the coalesced GPU arm dispatched to
    // GPU region presence; everything else (the default fused CPU path and the
    // coalesced SIMD arm) ran on SIMD/CPU.
    let gpu = crate::GPU_SCANNED_CHUNKS.load(Ordering::Relaxed).min(total);
    let simd = total - gpu;
    let hw = keyhog_scanner::hw_probe::probe_hardware();
    let line = if let Some(backend) = backend_override {
        format!("backend: {} (forced via --backend)", backend.label())
    } else if gpu > 0 && simd > 0 {
        format!(
            "backend: gpu-region-presence ({gpu} chunk(s)) + simd-regex ({simd} chunk(s)) - selected per batch by size"
        )
    } else if gpu > 0 {
        "backend: gpu-region-presence (selected for large-buffer batches)".to_string()
    } else if hw.gpu_available && !hw.gpu_is_software {
        let name = hw.gpu_name.as_deref().unwrap_or("a GPU").trim().to_string(); // LAW10: absent name/label => display default; reporting-only, recall-safe
        format!(
            "backend: simd-regex - {name} present but NOT engaged, and that is the \
             faster path here (measured). The GPU region-presence route still pays \
             host lowercase/coalescing, device dispatch/readback, and the shared CPU \
             phase-2 extraction tail. In the current evidence, SIMD wins for this \
             detector set through the measured range. Force the device path with \
             --backend gpu (parity / research), include it in calibration with \
             --autoroute-gpu, or run `keyhog backend`."
        )
    } else {
        "backend: simd-regex (no GPU available on this host)".to_string()
    };

    let palette = terminal_palette(ansi, false);
    eprintln!("{}INFO{} {line}", palette.cyan, palette.reset);
}

/// Live progress ticker - overwrites the previous line via CR every
/// 250 ms while the scan runs.
pub(crate) fn progress_ticker(done: Arc<std::sync::atomic::AtomicBool>, started: Instant) {
    use std::io::IsTerminal;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    if !std::io::stderr().is_terminal() {
        return;
    }
    let tick = Duration::from_millis(250);
    std::thread::sleep(tick);
    while !done.load(Ordering::Relaxed) {
        let scanned = crate::SCANNED_CHUNKS.load(Ordering::Relaxed);
        let total = crate::TOTAL_CHUNKS.load(Ordering::Relaxed);
        let findings = crate::FINDINGS_COUNT.load(Ordering::Relaxed);
        let elapsed = started.elapsed().as_secs_f64();
        let mut err = std::io::stderr().lock();
        let clear = terminal_clear_line_prefix(true);
        if let Err(error) = write!(
            err,
            "{clear}scanning {scanned}/{total} chunks · {findings} findings · {elapsed:.1}s"
        ) {
            tracing::debug!(%error, "progress redraw write error");
        }
        let _ = err.flush(); // LAW10: unused-binding marker; no runtime effect, not a fallback
        drop(err);
        std::thread::sleep(tick);
    }
    let mut err = std::io::stderr().lock();
    let _ = write!(err, "{}", terminal_clear_line_prefix(true)); // LAW10: unused-binding marker; no runtime effect, not a fallback
    let _ = err.flush(); // LAW10: unused-binding marker; no runtime effect, not a fallback
}

pub(crate) fn report_skip_summary(ansi: bool) {
    // Structured decode-through coverage gap — surfaced independently of the
    // walker skip counters (a scan can fully cover the tree yet still fail to
    // decode a malformed k8s Secret / tfstate / notebook). Law 10: a file that
    // MATCHED a structured format but failed to parse loses the secrets encoded
    // inside it (e.g. base64 in a k8s `data:` block), previously visible only at
    // `tracing::debug!`. The raw text was still scanned, so this is a partial,
    // not total, miss — the wording says so.
    let structured_failures = keyhog_scanner::telemetry::structured_parse_failure_count();
    if structured_failures > 0 {
        let msg = format!(
            "{structured_failures} file(s) matched a structured format (k8s Secret / \
             Terraform state / Jupyter notebook / docker-compose) but FAILED to parse: \
             secrets ENCODED inside them (e.g. base64 in a k8s `data:` block) were NOT \
             decoded. The raw text was still scanned. Fix the file syntax to scan their \
             encoded contents."
        );
        let palette = terminal_palette(ansi, false);
        eprintln!("{}WARN{} {msg}", palette.yellow, palette.reset);
    }

    let decode_truncations = keyhog_scanner::telemetry::decode_truncation_count();
    if decode_truncations > 0 {
        let msg = format!(
            "{decode_truncations} decode root(s) hit a decode-through budget/cap: \
             raw bytes were scanned, but deeper encoded layers may not have been \
             expanded. Re-scan the affected corpus with a narrower target or tuned \
             decode limits to prove encoded coverage."
        );
        let palette = terminal_palette(ansi, false);
        eprintln!("{}WARN{} {msg}", palette.yellow, palette.reset);
    }

    let invalid_detector_index_skips =
        keyhog_scanner::telemetry::invalid_detector_index_skip_count();
    if invalid_detector_index_skips > 0 {
        let msg = format!(
            "{invalid_detector_index_skips} scanner pattern(s) were NOT extracted: \
             compiled detector indices did not resolve to loaded detectors. This is a scanner \
             invariant violation; treat the scan as partial."
        );
        let palette = terminal_palette(ansi, false);
        eprintln!("{}WARN{} {msg}", palette.yellow, palette.reset);
    }

    let invalid_pattern_index_skips = keyhog_scanner::telemetry::invalid_pattern_index_skip_count();
    if invalid_pattern_index_skips > 0 {
        let msg = format!(
            "{invalid_pattern_index_skips} scanner pattern expansion edge(s) were NOT applied: \
             compiled pattern-index side data referenced patterns outside the trigger bitmap. \
             This is a scanner invariant violation; treat the scan as partial."
        );
        let palette = terminal_palette(ansi, false);
        eprintln!("{}WARN{} {msg}", palette.yellow, palette.reset);
    }

    let boundary_cardinality_mismatches =
        keyhog_scanner::telemetry::boundary_result_cardinality_mismatch_count();
    if boundary_cardinality_mismatches > 0 {
        let msg = format!(
            "{boundary_cardinality_mismatches} boundary reassembly pass(es) were NOT applied: \
             chunk/result cardinality drift made cross-chunk findings unsafe to append. \
             This is a scanner invariant violation; treat the scan as partial."
        );
        let palette = terminal_palette(ansi, false);
        eprintln!("{}WARN{} {msg}", palette.yellow, palette.reset);
    }

    let c = keyhog_sources::skip_counts();
    // Whether the binary source recorded any degradation/drop. Checked here so a
    // run whose ONLY coverage gap is a Ghidra fallback / unreadable binary (with
    // zero file-walk skips) still emits its summary line below.
    #[cfg(feature = "binary")]
    let binary_degraded = keyhog_sources::binary_degraded_to_strings();
    #[cfg(not(feature = "binary"))]
    let binary_degraded = 0;
    #[cfg(feature = "binary")]
    let binary_unreadable = keyhog_sources::binary_unreadable();
    #[cfg(not(feature = "binary"))]
    let binary_unreadable = 0;
    let binary_gap = binary_degraded > 0 || binary_unreadable > 0;
    // `binary_section_name_unresolved`, `source_truncated`, and
    // `structured_source_parse_failures` are partial-coverage signals and are
    // deliberately NOT part of `c.total()` (a file-skip total), so they are
    // checked explicitly here. A run whose ONLY gap is one of these must still
    // emit its summary line below.
    if c.total() == 0
        && c.binary_section_name_unresolved == 0
        && c.source_truncated == 0
        && c.structured_source_parse_failures == 0
        && !binary_gap
        && decode_truncations == 0
        && invalid_detector_index_skips == 0
        && invalid_pattern_index_skips == 0
        && boundary_cardinality_mismatches == 0
    {
        return;
    }
    // One stderr line per non-empty skip category, each with the reason AND the
    // remedy, so a previously-silent walker filter is visible (Law 10). The
    // unreadable category is the most important: it means the tree was NOT fully
    // covered, so a "no secrets found" result is not a clean bill of health.
    let mut lines: Vec<(String, bool)> = Vec::new();
    if c.over_max_size > 0 {
        lines.push((
            format!(
                "{} file(s) skipped: exceeded --max-file-size. Re-scan with a larger cap to include them.",
                c.over_max_size
            ),
            false,
        ));
    }
    if c.binary > 0 {
        lines.push((
            format!(
                "{} file(s) skipped: detected as binary (extension or content sniff) and not scanned as text.",
                c.binary
            ),
            false,
        ));
    }
    if c.excluded > 0 {
        lines.push((
            format!(
                "{} file(s) skipped: matched the default-exclusion list (lock/minified/vendored).",
                c.excluded
            ),
            false,
        ));
    }
    let non_binary_unreadable = c.unreadable.saturating_sub(binary_unreadable);
    if non_binary_unreadable > 0 {
        // `warn` = true: this one is highlighted because an unreadable file is an
        // unknown, not a clean file — the scan did not cover it.
        lines.push((
            format!(
                "{} file(s) NOT scanned: unreadable (permission denied or I/O error). These were NOT checked for secrets.",
                non_binary_unreadable
            ),
            true,
        ));
    }
    if c.archive_truncated > 0 {
        // `warn` = true: a bomb-truncated archive means part of it was NOT
        // scanned — partial coverage, an unknown, not a clean archive (Law 10).
        lines.push((
            format!(
                "{} archive(s) only PARTIALLY scanned: extraction was truncated by the decompression-bomb guard (uncompressed size exceeded 4x --max-file-size). Remaining entries were NOT checked for secrets.",
                c.archive_truncated
            ),
            true,
        ));
    }
    if c.binary_section_name_unresolved > 0 {
        // `warn` = true: a corrupt section-name string table means one or more
        // binary sections could not be identified, so a high-value
        // `.rodata`/`.data`/`__cstring` section may have been skipped — partial
        // binary coverage, not a clean binary (Law 10).
        lines.push((
            format!(
                "{} binary section(s) NOT scanned: their name could not be resolved (corrupt/truncated section-name string table). A secret-bearing section may have been skipped.",
                c.binary_section_name_unresolved
            ),
            true,
        ));
    }
    if c.source_truncated > 0 {
        lines.push((
            format!(
                "{} source scan(s) only PARTIALLY scanned: a source-level aggregate cap was reached before all input was exhausted.",
                c.source_truncated
            ),
            true,
        ));
    }
    if c.structured_source_parse_failures > 0 {
        lines.push((
            format!(
                "{} structured source file(s) only PARTIALLY scanned: format-specific expansion failed, so raw text was scanned but derived request/response/body chunks were not expanded.",
                c.structured_source_parse_failures
            ),
            true,
        ));
    }
    // Binary-source degradations (Law 10): Ghidra deep analysis that fell back to
    // shallow strings, and binaries dropped as unreadable. Each is already printed
    // loudly at its drop site; this end-of-scan roll-up makes the totals visible
    // alongside the other coverage gaps. Only compiled when the binary source is.
    #[cfg(feature = "binary")]
    {
        if binary_degraded > 0 {
            lines.push((
                format!(
                    "{binary_degraded} binary(ies) only SHALLOWLY scanned: Ghidra deep decompiler analysis failed or was too large, so only strings-mode extraction ran. Encoded/split secrets may have been missed."
                ),
                true,
            ));
        }
        if binary_unreadable > 0 {
            lines.push((
                format!(
                    "{binary_unreadable} binary(ies) NOT scanned: unreadable (permission denied or I/O error). These were NOT checked for secrets."
                ),
                true,
            ));
        }
    }
    for (msg, warn) in lines {
        let palette = terminal_palette(ansi, false);
        let (label, color) = if warn {
            ("FAIL", palette.red)
        } else {
            ("WARN", palette.yellow)
        };
        eprintln!("{color}{label}{} {msg}", palette.reset);
    }
}

/// Dump the captured dogfood events as a single JSON object on stderr.
pub(crate) fn dump_dogfood_trace() {
    if !keyhog_scanner::telemetry::is_dogfood_enabled() {
        return;
    }
    let events = keyhog_scanner::telemetry::drain_events();
    let suppressed = keyhog_scanner::telemetry::example_suppression_count();
    let payload = serde_json::json!({
        "dogfood": {
            "example_suppressions_total": suppressed,
            "events": events,
        }
    });
    eprintln!("{payload}");
}
