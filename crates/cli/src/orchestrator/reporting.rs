//! Scan completion reporting hooks (progress ticker, summaries, dogfood trace).

use keyhog_core::RawMatch;
use std::io::Write;
use std::sync::Arc;
use std::time::Instant;

/// Emit one redacted preview line per finding for `--stream` mode.
pub(crate) fn stream_finding_preview<W: Write>(w: &mut W, m: &RawMatch) {
    let path = m.location.file_path.as_deref().unwrap_or("<stdin>");
    let line = m
        .location
        .line
        .map(|n| n.to_string())
        .unwrap_or_else(|| "?".into());
    let redacted = keyhog_core::redact(&m.credential);
    let _ = writeln!(
        w,
        "[stream] {sev:<8} {service}/{detector}  {path}:{line}  {redacted}",
        sev = format!("{:?}", m.severity).to_uppercase(),
        service = m.service,
        detector = m.detector_id,
        path = path,
        line = line,
        redacted = redacted,
    );
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
    report_oversize_skip_summary(ansi);
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

pub(crate) fn report_oversize_skip_summary(ansi: bool) {
    use std::sync::atomic::Ordering;
    let skipped = keyhog_sources::SKIPPED_OVER_MAX_SIZE.load(Ordering::Relaxed);
    if skipped == 0 {
        return;
    }
    if ansi {
        eprintln!(
            "\x1b[33m{}\x1b[0m file(s) skipped: exceeded --max-file-size. Re-scan with a larger cap to include them.",
            skipped
        );
    } else {
        eprintln!(
            "{} file(s) skipped: exceeded --max-file-size. Re-scan with a larger cap to include them.",
            skipped
        );
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
