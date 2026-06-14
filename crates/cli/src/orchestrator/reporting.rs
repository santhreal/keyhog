//! Scan completion reporting hooks (progress ticker, summaries, dogfood trace).

use keyhog_core::VerifiedFinding;
use std::io::Write;
use std::sync::Arc;
use std::time::Instant;

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
    let path = f.location.file_path.as_deref().unwrap_or("<stdin>");
    let line = f
        .location
        .line
        .map(|n| n.to_string())
        .unwrap_or_else(|| "?".into());
    let _ = writeln!(
        w,
        "[stream] {sev:<8} {service}/{detector}  {path}:{line}  {redacted}",
        sev = format!("{:?}", f.severity).to_uppercase(),
        service = f.service,
        detector = f.detector_id,
        path = path,
        line = line,
        redacted = f.credential_redacted,
    );
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
    let _ = w.flush();
}

pub(crate) fn report_completion_summary(count: usize, elapsed: f64, ansi: bool) {
    if count == 0 {
        if ansi {
            eprintln!(
                "\n✨ Scan complete! Found \x1b[1;32m0\x1b[0m secrets in \x1b[33m{:.2}s\x1b[0m.",
                elapsed
            );
        } else {
            eprintln!("\n✨ Scan complete! Found 0 secrets in {:.2}s.", elapsed);
        }
    } else {
        if ansi {
            eprintln!(
                "\n✨ Scan complete! Found \x1b[1;31m{}\x1b[0m secrets in \x1b[33m{:.2}s\x1b[0m.",
                count, elapsed
            );
        } else {
            eprintln!(
                "\n✨ Scan complete! Found {} secrets in {:.2}s.",
                count, elapsed
            );
        }
    }
    report_skip_summary(ansi);
    report_backend_summary(ansi);
}

/// Surface which backend the autorouter ACTUALLY used this scan, and — when a
/// GPU is present but did not engage — WHY.
///
/// The per-batch routing decision (`select_backend_for_batch`) was previously
/// logged only at `tracing::debug!` (target `keyhog::routing`), invisible at the
/// default `keyhog=warn` verbosity. So a scan that CORRECTLY chose SIMD on a
/// small-file tree — where SIMD is measured ~2× faster than the GPU because the
/// per-dispatch + PCIe-copy cost isn't amortised by tiny files — read to the
/// operator as "the GPU autorouting is broken." This prints ONE completion line
/// stating the backend(s) used and the routing rationale, so the decision is
/// visible instead of buried (Law 10 / coherence). Reuses the scanner's existing
/// per-chunk telemetry (`gpu_dispatches` vs `files_scanned`); no new counters.
pub(crate) fn report_backend_summary(ansi: bool) {
    use std::sync::atomic::Ordering;
    let total = crate::SCANNED_CHUNKS.load(Ordering::Relaxed);
    if total == 0 {
        // Nothing was scanned (empty tree, source error, zero chunks) — there is
        // no routing decision to report.
        return;
    }
    // GPU_SCANNED_CHUNKS counts the chunks the coalesced GPU arm dispatched to
    // the megakernel; everything else (the default fused CPU path and the
    // coalesced SIMD arm) ran on SIMD/CPU.
    let gpu = crate::GPU_SCANNED_CHUNKS.load(Ordering::Relaxed).min(total);
    let simd = total - gpu;
    let hw = keyhog_scanner::hw_probe::probe_hardware();
    let forced = std::env::var("KEYHOG_BACKEND")
        .ok()
        .filter(|s| !s.trim().is_empty());

    let line = if let Some(b) = &forced {
        let engine = if gpu > 0 { "gpu-zero-copy" } else { "simd-regex" };
        format!("backend: {engine} (forced via KEYHOG_BACKEND={b})")
    } else if gpu > 0 && simd > 0 {
        format!(
            "backend: gpu-zero-copy ({gpu} chunk(s)) + simd-regex ({simd} chunk(s)) — auto-routed per batch by size"
        )
    } else if gpu > 0 {
        "backend: gpu-zero-copy (auto-routed: large-buffer batches)".to_string()
    } else if hw.gpu_available && !hw.gpu_is_software {
        let name = hw.gpu_name.as_deref().unwrap_or("a GPU").trim().to_string();
        format!(
            "backend: simd-regex — {name} present but NOT engaged. keyhog runs default \
             filesystem scans on the parallel CPU path (measured fastest for real source \
             trees) and reserves the GPU for large-buffer batch scans where its dispatch \
             cost is amortised. Force the GPU with KEYHOG_BACKEND=gpu, or run \
             `keyhog backend` for the routing matrix."
        )
    } else {
        "backend: simd-regex (no GPU available on this host)".to_string()
    };

    if ansi {
        eprintln!("\x1b[36m⚙ {line}\x1b[0m");
    } else {
        eprintln!("⚙ {line}");
    }
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
        let _ = write!(
            err,
            "\x1b[2K\rscanning {scanned}/{total} chunks · {findings} findings · {elapsed:.1}s"
        );
        let _ = err.flush();
        drop(err);
        std::thread::sleep(tick);
    }
    let mut err = std::io::stderr().lock();
    let _ = write!(err, "\x1b[2K\r");
    let _ = err.flush();
}

pub(crate) fn report_skip_summary(ansi: bool) {
    let c = keyhog_sources::skip_counts();
    if c.total() == 0 {
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
    if c.unreadable > 0 {
        // `warn` = true: this one is highlighted because an unreadable file is an
        // unknown, not a clean file — the scan did not cover it.
        lines.push((
            format!(
                "{} file(s) NOT scanned: unreadable (permission denied or I/O error). These were NOT checked for secrets.",
                c.unreadable
            ),
            true,
        ));
    }
    for (msg, warn) in lines {
        if ansi {
            let color = if warn { "\x1b[31m" } else { "\x1b[33m" };
            eprintln!("{color}{msg}\x1b[0m");
        } else {
            eprintln!("{msg}");
        }
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
