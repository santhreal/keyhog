//! Scan completion reporting hooks (progress ticker, summaries, dogfood trace).

use keyhog_core::{Severity, VerifiedFinding};
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

fn colorize(text: String, color_code: &str, color: bool) -> String {
    if color {
        format!("{color_code}{text}{C_RESET}")
    } else {
        text
    }
}

fn count_token(count: usize, label: &str, color_code: &str, color: bool) -> String {
    colorize(format!("{count} {label}"), color_code, color)
}

fn dot_join(parts: &[String], color: bool) -> String {
    let sep = if color {
        format!("{C_MUTED} · {C_RESET}")
    } else {
        " · ".to_string()
    };
    parts.join(&sep)
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::ClientSafe => "client-safe",
        Severity::Info => "info",
    }
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
            count_token(
                count,
                severity_label(severity),
                severity_color(severity),
                color,
            )
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
            "{muted}↳ verification: {amber}not checked{reset}{muted} — liveness check did not run; pass {brand}--verify{reset}{muted} \
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

/// keyhog brand yellow (#ffd60a) and a dimmed rail, as 24-bit truecolor SGR.
/// Gated behind the ticker's `color` flag (TTY && !NO_COLOR) so piped/`NO_COLOR`
/// output stays plain. Truecolor degrades gracefully to the nearest colour on
/// 256/16-colour terminals; the layout is identical with or without colour.
const C_BRAND: &str = "\x1b[38;2;255;214;10m";
const C_CRITICAL: &str = "\x1b[38;2;255;69;58m";
const C_HIGH: &str = "\x1b[38;2;255;159;10m";
const C_MEDIUM: &str = "\x1b[38;2;255;214;10m";
const C_LOW: &str = "\x1b[38;2;100;210;255m";
const C_SAFE: &str = "\x1b[38;2;48;209;88m";
const C_AMBER: &str = "\x1b[38;2;255;159;10m";
const C_RAIL: &str = "\x1b[38;2;74;74;82m";
const C_MUTED: &str = "\x1b[38;2;138;138;150m";
const C_BOLD: &str = "\x1b[1m";
const C_RESET: &str = "\x1b[0m";

/// Smooth determinate bar with 1/8-cell resolution: full `█` cells, one partial
/// glyph for the fractional cell, then a dimmed `░` rail. The partial-block
/// transition is what makes the fill look continuous rather than steppy.
fn render_progress_bar(frac: f64, width: usize, color: bool) -> String {
    const PARTIALS: [char; 8] = [' ', '▏', '▎', '▍', '▌', '▋', '▊', '▉'];
    let frac = frac.clamp(0.0, 1.0);
    let eighths = (frac * width as f64 * 8.0).round() as usize;
    let full = (eighths / 8).min(width);
    let rem = eighths % 8;
    let mut fill = "█".repeat(full);
    let mut used = full;
    if full < width && rem > 0 {
        fill.push(PARTIALS[rem]);
        used += 1;
    }
    let rail = "░".repeat(width.saturating_sub(used));
    if color {
        // Only emit a colour escape for a segment that actually has cells, so an
        // empty fill (0%) or full bar (100%) carries no dangling SGR codes.
        let mut s = String::new();
        if !fill.is_empty() {
            s.push_str(C_BRAND);
            s.push_str(&fill);
        }
        if !rail.is_empty() {
            s.push_str(C_RAIL);
            s.push_str(&rail);
        }
        s.push_str(C_RESET);
        s
    } else {
        format!("{fill}{rail}")
    }
}

/// Indeterminate "warming up" sweep — a lit band that slides across a dim rail,
/// shown before the first chunk is dispatched (`TOTAL_CHUNKS == 0`) so the line
/// is visibly alive during backend warm-up / file discovery instead of a frozen
/// "scanning 0/0".
fn render_indeterminate_bar(phase: usize, width: usize, color: bool) -> String {
    let band = 4usize;
    let span = width + band;
    let head = phase % span;
    let mut cells = String::with_capacity(width * 4);
    for i in 0..width {
        let lit = head >= i && head < i + band;
        if color {
            cells.push_str(if lit { C_AMBER } else { C_RAIL });
        }
        cells.push(if lit { '█' } else { '░' });
    }
    if color {
        cells.push_str(C_RESET);
    }
    cells
}

/// Format an elapsed/eta duration compactly: `8.2s`, or `1m04s` past a minute.
fn fmt_secs(s: f64) -> String {
    if s < 59.95 {
        format!("{s:.1}s")
    } else {
        let total = s.round() as u64;
        let m = total / 60;
        let r = total % 60;
        format!("{m}m{r:02}s")
    }
}

/// Build one progress line (without the CR/clear prefix) from a counter
/// snapshot. Pure — so the exact layout is unit-testable and can be visually
/// iterated with a frame-dump test, instead of needing a multi-second live scan.
fn render_ticker_line(
    scanned: usize,
    total: usize,
    findings: usize,
    elapsed: f64,
    frame: usize,
    color: bool,
) -> String {
    const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    const BAR_WIDTH: usize = 22;
    let (brand, amber, muted, rail, bold, reset) = if color {
        (C_BRAND, C_AMBER, C_MUTED, C_RAIL, C_BOLD, C_RESET)
    } else {
        ("", "", "", "", "", "")
    };
    let spin = FRAMES[frame % FRAMES.len()];
    // Findings count lights up the instant the first one lands; noun agrees in number.
    let noun = if findings == 1 { "finding" } else { "findings" };
    let find_seg = if findings > 0 {
        format!("{bold}{amber}{findings}{reset} {muted}{noun}{reset}")
    } else {
        format!("{muted}0 {noun}{reset}")
    };
    if total == 0 {
        let sweep = render_indeterminate_bar(frame, BAR_WIDTH, color);
        format!(
            "{brand}{spin}{reset} {bold}preparing{reset} {muted}·{reset} {sweep} {muted}·{reset} warming backend, discovering files {muted}·{reset} {find_seg} {muted}·{reset} {muted}{}{reset}",
            fmt_secs(elapsed)
        )
    } else {
        let frac = scanned as f64 / total as f64;
        let pct = (frac * 100.0).floor() as u64;
        let bar = render_progress_bar(frac, BAR_WIDTH, color);
        let rate = if elapsed > 0.05 {
            scanned as f64 / elapsed
        } else {
            0.0
        };
        let eta = if rate > 0.5 && scanned < total {
            format!(
                "  {muted}eta {}{reset}",
                fmt_secs((total - scanned) as f64 / rate)
            )
        } else {
            String::new()
        };
        let label = if scanned >= total {
            "finalizing"
        } else {
            "scanning"
        };
        format!(
            "{brand}{spin}{reset} {bold}{label}{reset} {rail}▕{reset}{bar}{rail}▏{reset} {bold}{pct:>3}%{reset}  {muted}{scanned}/{total}{reset}  {muted}·{reset}  {find_seg}  {muted}·{reset}  {muted}{rate:.0}/s{reset}  {muted}·{reset}  {muted}{}{reset}{eta}",
            fmt_secs(elapsed)
        )
    }
}

fn render_verification_ticker_line(
    total: usize,
    elapsed: f64,
    frame: usize,
    color: bool,
) -> String {
    const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    const BAR_WIDTH: usize = 22;
    let (brand, muted, bold, reset) = if color {
        (C_BRAND, C_MUTED, C_BOLD, C_RESET)
    } else {
        ("", "", "", "")
    };
    let spin = FRAMES[frame % FRAMES.len()];
    let sweep = render_indeterminate_bar(frame, BAR_WIDTH, color);
    let noun = if total == 1 { "secret" } else { "secrets" };
    format!(
        "{brand}{spin}{reset} {bold}verifying{reset} {muted}·{reset} {sweep} {muted}·{reset} checking {bold}{total}{reset} {noun} {muted}·{reset} {muted}{}{reset}",
        fmt_secs(elapsed)
    )
}

/// Live progress ticker - overwrites the previous line via CR.
///
/// Paints IMMEDIATELY (no pre-sleep) and animates every 90 ms so the line is
/// visibly alive from the first frame. Two phases, both kept on ONE rewritten
/// line:
/// - `TOTAL_CHUNKS == 0` (backend warm-up / file discovery): a brand-coloured
///   spinner + an indeterminate sweep + the elapsed clock — never a frozen
///   "scanning 0/0".
/// - chunks streaming: a smooth determinate bar with percent, scanned/total,
///   live findings (lit amber the moment the first one lands), throughput
///   (chunks/s) and a computed ETA.
pub(crate) fn progress_ticker(done: Arc<std::sync::atomic::AtomicBool>, started: Instant) {
    use std::io::IsTerminal;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    if !std::io::stderr().is_terminal() {
        return;
    }
    let color = std::env::var_os("NO_COLOR").is_none();
    let tick = Duration::from_millis(90);
    let mut frame = 0usize;
    loop {
        let scanned = crate::SCANNED_CHUNKS.load(Ordering::Relaxed);
        let total = crate::TOTAL_CHUNKS.load(Ordering::Relaxed);
        let findings = crate::FINDINGS_COUNT.load(Ordering::Relaxed);
        let elapsed = started.elapsed().as_secs_f64();
        let clear = terminal_clear_line_prefix(true);
        let line = render_ticker_line(scanned, total, findings, elapsed, frame, color);
        let mut err = std::io::stderr().lock();
        if let Err(error) = write!(err, "{clear}{line}") {
            tracing::debug!(%error, "progress redraw write error");
        }
        let _ = err.flush(); // LAW10: unused-binding marker; no runtime effect, not a fallback
        drop(err);
        // Check AFTER painting so spawn always yields one immediate frame and the
        // terminal state at completion is the last thing rendered before clear.
        if done.load(Ordering::Relaxed) {
            break;
        }
        std::thread::sleep(tick);
        frame = frame.wrapping_add(1);
    }
    let mut err = std::io::stderr().lock();
    let _ = write!(err, "{}", terminal_clear_line_prefix(true)); // LAW10: unused-binding marker; no runtime effect, not a fallback
    let _ = err.flush(); // LAW10: unused-binding marker; no runtime effect, not a fallback
}

/// Live verification ticker. Verification happens after scan chunks have
/// completed, so the scan ticker is no longer alive. This keeps `--verify`
/// operator-visible during the network phase instead of going quiet between
/// scanning and the final report.
pub(crate) fn verification_ticker(
    done: Arc<std::sync::atomic::AtomicBool>,
    started: Instant,
    total: usize,
) {
    use std::io::IsTerminal;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    if !std::io::stderr().is_terminal() {
        return;
    }
    let color = std::env::var_os("NO_COLOR").is_none();
    let tick = Duration::from_millis(90);
    let mut frame = 0usize;
    loop {
        let elapsed = started.elapsed().as_secs_f64();
        let clear = terminal_clear_line_prefix(true);
        let line = render_verification_ticker_line(total, elapsed, frame, color);
        let mut err = std::io::stderr().lock();
        if let Err(error) = write!(err, "{clear}{line}") {
            tracing::debug!(%error, "verification progress redraw write error");
        }
        let _ = err.flush(); // LAW10: unused-binding marker; no runtime effect, not a fallback
        drop(err);
        if done.load(Ordering::Relaxed) {
            break;
        }
        std::thread::sleep(tick);
        frame = frame.wrapping_add(1);
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
        eprintln!("{}WARN {msg}{}", palette.yellow, palette.reset);
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
        eprintln!("{}WARN {msg}{}", palette.yellow, palette.reset);
    }

    let invalid_pattern_index_skips = keyhog_scanner::telemetry::invalid_pattern_index_skip_count();
    if invalid_pattern_index_skips > 0 {
        let msg = format!(
            "{invalid_pattern_index_skips} scanner pattern expansion edge(s) were NOT applied: \
             compiled pattern-index side data referenced patterns outside the trigger bitmap. \
             This is a scanner invariant violation; treat the scan as partial."
        );
        let palette = terminal_palette(ansi, false);
        eprintln!("{}WARN {msg}{}", palette.yellow, palette.reset);
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
        eprintln!("{}WARN {msg}{}", palette.yellow, palette.reset);
    }

    let line_offset_mapping_mismatches =
        keyhog_scanner::telemetry::line_offset_mapping_mismatch_count();
    if line_offset_mapping_mismatches > 0 {
        let msg = format!(
            "{line_offset_mapping_mismatches} multiline attribution mapping(s) used a fallback \
             source offset because line-offset metadata was inconsistent. Findings were still \
             emitted, but reported locations may be approximate; treat the scan as partial."
        );
        let palette = terminal_palette(ansi, false);
        eprintln!("{}WARN {msg}{}", palette.yellow, palette.reset);
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
        && c.archive_duplicate_scan_unavailable == 0
        && !binary_gap
        && decode_truncations == 0
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
    if c.archive_duplicate_scan_unavailable > 0 {
        // `warn` = true: duplicate-entry detection could not run (zip64 / malformed
        // central directory), so the standard parser scanned the archive but may
        // have missed a duplicated/shadow central-directory entry — partial
        // coverage, an evasion-bypass surface, not a clean archive (Law 10).
        lines.push((
            format!(
                "{} archive(s) scanned WITHOUT duplicate-entry detection: a zip64 or malformed central directory prevented it, so a duplicated/shadow entry hiding a secret may have been missed.",
                c.archive_duplicate_scan_unavailable
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
    let payload = serde_json::json!({
        "dogfood": {
            "example_suppressions_total": suppressed,
            "events": events,
        }
    });
    eprintln!("{payload}");
}

#[cfg(test)]
mod ticker_tests {
    use super::{
        fmt_secs, render_progress_bar, render_severity_line, render_ticker_line,
        render_verification_line, render_verification_ticker_line, verification_breakdown,
    };

    fn finding(v: keyhog_core::VerificationResult) -> keyhog_core::VerifiedFinding {
        use std::borrow::Cow;
        use std::sync::Arc;
        keyhog_core::VerifiedFinding {
            detector_id: Arc::from("aws-access-key"),
            detector_name: Arc::from("AWS Key"),
            service: Arc::from("aws"),
            severity: keyhog_core::Severity::High,
            credential_redacted: Cow::Borrowed("AKIA..."),
            credential_hash: [0u8; 32].into(),
            location: keyhog_core::MatchLocation {
                source: Arc::from("filesystem"),
                file_path: Some(Arc::from("a.txt")),
                line: Some(1),
                offset: 0,
                commit: None,
                author: None,
                date: None,
            },
            verification: v,
            metadata: std::collections::HashMap::new(),
            additional_locations: vec![],
            confidence: Some(0.9),
        }
    }

    fn finding_with(
        severity: keyhog_core::Severity,
        v: keyhog_core::VerificationResult,
    ) -> keyhog_core::VerifiedFinding {
        let mut finding = finding(v);
        finding.severity = severity;
        finding
    }

    #[test]
    fn breakdown_tallies_each_verification_state() {
        use keyhog_core::VerificationResult as V;
        let findings = vec![
            finding(V::Live),
            finding(V::Live),
            finding(V::Revoked),
            finding(V::Dead),
            finding(V::Skipped),
            finding(V::Unverifiable),
            finding(V::RateLimited),
            finding(V::Error("boom".to_string())),
        ];
        let b = verification_breakdown(&findings);
        assert_eq!(b.live, 2);
        assert_eq!(b.inactive, 2, "revoked + dead");
        assert_eq!(b.skipped, 1);
        assert_eq!(b.unverifiable, 1);
        assert_eq!(b.incomplete, 2, "ratelimited + error");
    }

    #[test]
    fn all_skipped_says_verification_did_not_run() {
        use keyhog_core::VerificationResult as V;
        let findings = vec![
            finding(V::Skipped),
            finding(V::Skipped),
            finding(V::Skipped),
        ];
        let b = verification_breakdown(&findings);
        let line =
            render_verification_line(&b, findings.len(), false).expect("line for >0 findings");
        assert!(
            line.contains("liveness check did not run"),
            "honest 'we did not try': {line}"
        );
        assert!(
            line.contains("not checked"),
            "posture should be explicit: {line}"
        );
        assert!(line.contains("--verify"), "points at the flag: {line}");
        // The all-skipped branch emits the prose message, never a count
        // breakdown — so it cannot read as "1 live", and carries no `·` separator.
        assert!(
            !line.contains('·'),
            "all-skipped uses the prose message, not a breakdown: {line}"
        );
    }

    #[test]
    fn mixed_states_render_breakdown_omitting_zeros() {
        use keyhog_core::VerificationResult as V;
        let findings = vec![finding(V::Live), finding(V::Revoked), finding(V::Skipped)];
        let b = verification_breakdown(&findings);
        let line = render_verification_line(&b, findings.len(), false).unwrap();
        assert!(line.contains("1 live"), "{line}");
        assert!(line.contains("1 revoked/dead"), "{line}");
        assert!(line.contains("1 not checked"), "{line}");
        assert!(line.contains("verification:"), "{line}");
        assert!(
            !line.contains("no verifier"),
            "zero category omitted: {line}"
        );
        assert!(
            !line.contains("inconclusive"),
            "zero category omitted: {line}"
        );
    }

    #[test]
    fn no_findings_yields_no_verification_line() {
        let b = verification_breakdown(&[]);
        assert_eq!(render_verification_line(&b, 0, false), None);
    }

    #[test]
    fn severity_summary_is_heat_ordered_and_color_gated() {
        use keyhog_core::Severity as S;
        use keyhog_core::VerificationResult as V;
        let findings = vec![
            finding_with(S::Low, V::Skipped),
            finding_with(S::Critical, V::Skipped),
            finding_with(S::High, V::Skipped),
            finding_with(S::ClientSafe, V::Skipped),
            finding_with(S::High, V::Skipped),
        ];
        let plain = render_severity_line(&findings, false).unwrap();
        assert_eq!(
            plain,
            "↳ severity: 1 critical · 2 high · 1 low · 1 client-safe"
        );
        assert!(!plain.contains('\x1b'), "plain severity line: {plain:?}");
        let colored = render_severity_line(&findings, true).unwrap();
        assert!(
            colored.contains('\x1b'),
            "colored severity line should use heat SGR codes: {colored:?}"
        );
        assert!(colored.contains("1 critical"), "{colored}");
        assert!(colored.contains("2 high"), "{colored}");
        assert_eq!(render_severity_line(&[], true), None);
    }

    #[test]
    fn verification_summary_colours_posture_without_plain_ansi() {
        use keyhog_core::VerificationResult as V;
        let findings = vec![
            finding(V::Live),
            finding(V::Skipped),
            finding(V::Error("e".into())),
        ];
        let b = verification_breakdown(&findings);
        let plain = render_verification_line(&b, findings.len(), false).unwrap();
        assert_eq!(
            plain,
            "↳ verification: 1 live · 1 not checked · 1 inconclusive"
        );
        assert!(
            !plain.contains('\x1b'),
            "plain verification line: {plain:?}"
        );
        let colored = render_verification_line(&b, findings.len(), true).unwrap();
        assert!(
            colored.contains('\x1b'),
            "colored verification line should use posture SGR codes: {colored:?}"
        );
        assert!(colored.contains("1 live"), "{colored}");
        assert!(colored.contains("1 not checked"), "{colored}");
    }

    #[test]
    fn verification_line_is_color_gated() {
        use keyhog_core::VerificationResult as V;
        let b = verification_breakdown(&[finding(V::Live)]);
        assert!(
            !render_verification_line(&b, 1, false)
                .unwrap()
                .contains('\x1b'),
            "plain mode is ansi-free"
        );
        assert!(
            render_verification_line(&b, 1, true)
                .unwrap()
                .contains('\x1b'),
            "color mode carries SGR codes"
        );
    }

    #[test]
    fn progress_bar_endpoints_and_width() {
        // Empty: all rail, no full blocks; correct cell count.
        let empty = render_progress_bar(0.0, 22, false);
        assert_eq!(empty.chars().count(), 22, "bar must be exactly width cells");
        assert_eq!(empty.chars().filter(|&c| c == '█').count(), 0);
        assert!(empty.chars().all(|c| c == '░'));
        // Full: all full blocks.
        let full = render_progress_bar(1.0, 22, false);
        assert_eq!(full.chars().filter(|&c| c == '█').count(), 22);
        assert!(!full.contains('░'));
        // Half: ~11 full blocks (1/8-cell resolution rounds 0.5*22=11.0).
        let half = render_progress_bar(0.5, 22, false);
        assert_eq!(half.chars().filter(|&c| c == '█').count(), 11);
        // Clamp: out-of-range fractions never panic or overflow the width.
        assert_eq!(
            render_progress_bar(2.0, 22, false)
                .chars()
                .filter(|&c| c == '█')
                .count(),
            22
        );
        assert_eq!(render_progress_bar(-1.0, 22, false).chars().count(), 22);
    }

    #[test]
    fn scanning_line_carries_pct_counts_findings_and_stage() {
        let line = render_ticker_line(50, 100, 3, 2.0, 0, false);
        assert!(line.contains("50%"), "percent: {line}");
        assert!(line.contains("50/100"), "scanned/total: {line}");
        assert!(line.contains("3 findings"), "lit findings: {line}");
        assert!(line.contains("scanning"), "stage label: {line}");
        // At 100% scanned the stage flips to finalizing and drops the ETA.
        let done = render_ticker_line(100, 100, 3, 2.0, 0, false);
        assert!(done.contains("finalizing"), "finalizing at full: {done}");
        assert!(!done.contains("eta"), "no eta once scanned==total: {done}");
    }

    #[test]
    fn preparing_line_used_before_first_chunk() {
        let line = render_ticker_line(0, 0, 0, 0.4, 0, false);
        assert!(line.contains("preparing"), "pre-dispatch label: {line}");
        assert!(line.contains("0 findings"));
        assert!(
            !line.contains('%'),
            "no percent before total is known: {line}"
        );
    }

    #[test]
    fn verification_line_carries_stage_and_candidate_count() {
        let line = render_verification_ticker_line(3, 1.2, 0, false);
        assert!(line.contains("verifying"), "stage label: {line}");
        assert!(
            line.contains("checking 3 secrets"),
            "candidate count: {line}"
        );
        assert!(
            !line.contains('%'),
            "verification is indeterminate until verifier results return: {line}"
        );
        let one = render_verification_ticker_line(1, 1.2, 0, false);
        assert!(one.contains("checking 1 secret"), "singular noun: {one}");
    }

    #[test]
    fn plain_mode_emits_no_ansi_color_mode_does() {
        let plain = render_ticker_line(50, 100, 3, 2.0, 0, false);
        assert!(
            !plain.contains('\x1b'),
            "NO_COLOR line must be ansi-free: {plain:?}"
        );
        let verify_plain = render_verification_ticker_line(3, 1.2, 0, false);
        assert!(
            !verify_plain.contains('\x1b'),
            "plain verification line must be ansi-free: {verify_plain:?}"
        );
        let colored = render_ticker_line(50, 100, 3, 2.0, 0, true);
        assert!(colored.contains('\x1b'), "color line must carry SGR codes");
        let verify_colored = render_verification_ticker_line(3, 1.2, 0, true);
        assert!(
            verify_colored.contains('\x1b'),
            "color verification line must carry SGR codes"
        );
    }

    #[test]
    fn fmt_secs_switches_to_minutes_past_a_minute() {
        assert_eq!(fmt_secs(8.25), "8.2s");
        assert_eq!(fmt_secs(59.94), "59.9s");
        assert_eq!(fmt_secs(59.95), "1m00s");
        assert_eq!(fmt_secs(59.96), "1m00s");
        assert_eq!(fmt_secs(64.0), "1m04s");
        assert_eq!(fmt_secs(119.6), "2m00s");
    }

    /// Visual harness: `cargo test -p keyhog dump_ticker_frames -- --ignored --nocapture`
    /// prints a full color frame sequence so the layout can be eyeballed without
    /// a multi-second live scan. Ignored by default (it asserts nothing).
    #[test]
    #[ignore]
    fn dump_ticker_frames() {
        println!("\n--- preparing (indeterminate sweep) ---");
        for f in [0usize, 3, 6, 9, 12] {
            println!("{}", render_ticker_line(0, 0, 0, f as f64 * 0.1, f, true));
        }
        println!("\n--- scanning (determinate bar) ---");
        for (s, fnd) in [(0, 0), (550, 0), (1250, 1), (1980, 3), (2503, 3)] {
            let line = render_ticker_line(s, 2503, fnd, 1.0 + s as f64 / 600.0, s / 90, true);
            println!("{line}");
        }
        println!();
    }
}
