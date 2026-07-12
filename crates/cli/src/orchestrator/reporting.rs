//! Scan completion reporting hooks (progress ticker, summaries, dogfood trace).

use keyhog_core::{Severity, VerifiedFinding};
use std::io::Write;
use std::sync::atomic::AtomicBool;
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
/// exit code, but the only terminal output was a `tracing::error!` — filtered
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
pub(crate) fn secret_noun(count: usize) -> &'static str {
    if count == 1 {
        "secret"
    } else {
        "secrets"
    }
}

/// Singular/plural noun for a finding count (scan/reporting tickers).
pub(crate) fn finding_noun(count: usize) -> &'static str {
    if count == 1 {
        "finding"
    } else {
        "findings"
    }
}

fn dot_join(parts: &[String], color: bool) -> String {
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
        // Pluralize the noun so a single finding reads "Found 1 secret", not
        // "1 secrets"; matches the stdout `Results` footer's `secret{plural}`.
        let noun = secret_noun(count);
        eprintln!(
            "\nScan complete. Found {}{}{} {} in {}{:.2}s{}.",
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

// keyhog brand yellow (#ffd60a), severity heat colours and a dimmed rail, as
// 24-bit truecolor SGR. The escape literals live in `crate::style` (the one CLI
// file exempt from the no-raw-ANSI gate); imported here under the local `C_*`
// names the ticker/summary renderers use. Gated behind the ticker's `color`
// flag (TTY && !NO_COLOR) so piped/`NO_COLOR` output stays plain. Truecolor
// degrades gracefully to the nearest colour on 256/16-colour terminals; the
// layout is identical with or without colour.
use crate::style::{
    SEV_AMBER as C_AMBER, SEV_BOLD as C_BOLD, SEV_BRAND as C_BRAND, SEV_CRITICAL as C_CRITICAL,
    SEV_HIGH as C_HIGH, SEV_LOW as C_LOW, SEV_MEDIUM as C_MEDIUM, SEV_MUTED as C_MUTED,
    SEV_RAIL as C_RAIL, SEV_RESET as C_RESET, SEV_SAFE as C_SAFE,
};

/// Braille spinner cycle for every phase ticker (scan / verification / reporting).
/// Single owner so all three tickers spin identically; `frame % FRAMES.len()`
/// indexes it. Ten frames give a smooth 1/10-turn step per tick.
const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Progress/indeterminate bar cell width shared by every phase ticker, so the
/// determinate scan bar and the indeterminate warm-up/verify/report sweeps line
/// up to the same column. Single owner — the three tickers must not drift apart.
const BAR_WIDTH: usize = 22;

/// Smooth determinate bar with 1/8-cell resolution: full `█` cells, one partial
/// glyph for the fractional cell, then a dimmed `░` rail. The partial-block
/// transition is what makes the fill look continuous rather than steppy.
pub(crate) fn render_progress_bar(frac: f64, width: usize, color: bool) -> String {
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
pub(crate) fn fmt_secs(s: f64) -> String {
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
pub(crate) fn render_ticker_line(
    scanned: usize,
    total: usize,
    findings: usize,
    elapsed: f64,
    frame: usize,
    color: bool,
) -> String {
    let (brand, amber, muted, rail, bold, reset) = if color {
        (C_BRAND, C_AMBER, C_MUTED, C_RAIL, C_BOLD, C_RESET)
    } else {
        ("", "", "", "", "", "")
    };
    let spin = FRAMES[frame % FRAMES.len()];
    // Findings count lights up the instant the first one lands; noun agrees in number.
    let noun = finding_noun(findings);
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
        // `scanned` and `total` are independent Relaxed atomics sampled at two
        // instants, so a fresh `scanned` against a stale `total` can transiently
        // read `scanned > total`. Clamp the DISPLAYED count so the bar, the
        // percentage, and the `n/total` ratio can never show ">100%" or
        // "1001/1000"; the true underlying rate/eta still use the raw `scanned`.
        let shown = scanned.min(total);
        let frac = shown as f64 / total as f64;
        let pct = (frac * 100.0).floor() as u64;
        let bar = render_progress_bar(frac, BAR_WIDTH, color);
        let rate = if elapsed > 0.05 {
            scanned as f64 / elapsed
        } else {
            0.0
        };
        let eta = if rate > 0.5 && shown < total {
            format!(
                "  {muted}eta {}{reset}",
                fmt_secs((total - shown) as f64 / rate)
            )
        } else {
            String::new()
        };
        let label = if shown >= total {
            "finalizing"
        } else {
            "scanning"
        };
        format!(
            "{brand}{spin}{reset} {bold}{label}{reset} {rail}▕{reset}{bar}{rail}▏{reset} {bold}{pct:>3}%{reset}  {muted}{shown}/{total}{reset}  {muted}·{reset}  {find_seg}  {muted}·{reset}  {muted}{rate:.0}/s{reset}  {muted}·{reset}  {muted}{}{reset}{eta}",
            fmt_secs(elapsed)
        )
    }
}

pub(crate) fn render_verification_ticker_line(
    total: usize,
    elapsed: f64,
    frame: usize,
    color: bool,
) -> String {
    let (brand, muted, bold, reset) = if color {
        (C_BRAND, C_MUTED, C_BOLD, C_RESET)
    } else {
        ("", "", "", "")
    };
    let spin = FRAMES[frame % FRAMES.len()];
    let sweep = render_indeterminate_bar(frame, BAR_WIDTH, color);
    let noun = secret_noun(total);
    format!(
        "{brand}{spin}{reset} {bold}verifying{reset} {muted}·{reset} {sweep} {muted}·{reset} checking {bold}{total}{reset} {noun} {muted}·{reset} {muted}{}{reset}",
        fmt_secs(elapsed)
    )
}

pub(crate) fn render_reporting_ticker_line(
    total: usize,
    elapsed: f64,
    frame: usize,
    color: bool,
) -> String {
    let (brand, muted, bold, reset) = if color {
        (C_BRAND, C_MUTED, C_BOLD, C_RESET)
    } else {
        ("", "", "", "")
    };
    let spin = FRAMES[frame % FRAMES.len()];
    let sweep = render_indeterminate_bar(frame, BAR_WIDTH, color);
    let noun = finding_noun(total);
    format!(
        "{brand}{spin}{reset} {bold}reporting{reset} {muted}·{reset} {sweep} {muted}·{reset} writing {bold}{total}{reset} {noun} {muted}·{reset} {muted}{}{reset}",
        fmt_secs(elapsed)
    )
}

/// Drop-guarded lifecycle for phase progress threads.
///
/// Cleanup-boundary regression coverage lives in the relocated integration test
/// `ticker_guard_stop_signals_and_joins_worker`
/// (crates/cli/tests/unit/orchestrator_reporting_render.rs): it spawns a guard,
/// lets the worker tick, then asserts `Drop` signals `done` and joins the thread.
pub(crate) struct TickerGuard {
    done: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    label: &'static str,
}

impl TickerGuard {
    pub(crate) fn spawn<F>(label: &'static str, run: F) -> Self
    where
        F: FnOnce(Arc<AtomicBool>, Instant) + Send + 'static,
    {
        let done = Arc::new(AtomicBool::new(false));
        let ticker_done = Arc::clone(&done);
        let started = Instant::now();
        let handle = std::thread::spawn(move || run(ticker_done, started));
        Self {
            done,
            handle: Some(handle),
            label,
        }
    }

    pub(crate) fn stop(mut self) {
        self.stop_inner();
    }

    fn stop_inner(&mut self) {
        use std::sync::atomic::Ordering;
        self.done.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            if handle.join().is_err() {
                tracing::debug!(
                    ticker = self.label,
                    "progress thread panicked while shutting down"
                );
            }
        }
    }
}

impl Drop for TickerGuard {
    fn drop(&mut self) {
        self.stop_inner();
    }
}

fn terminal_ticker_loop<F>(
    done: Arc<AtomicBool>,
    started: Instant,
    redraw_error_label: &'static str,
    mut render: F,
) where
    F: FnMut(f64, usize, bool) -> String,
{
    use std::io::IsTerminal;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    if !std::io::stderr().is_terminal() {
        return;
    }
    // stderr is a TTY here; honour the NO_COLOR convention via the centralized,
    // env-read-allowlisted helper (the orchestrator must not read env directly).
    let color = !crate::style::no_color_requested();
    let tick = Duration::from_millis(90);
    let mut frame = 0usize;
    loop {
        let elapsed = started.elapsed().as_secs_f64();
        let clear = terminal_clear_line_prefix(true);
        let line = render(elapsed, frame, color);
        let mut err = std::io::stderr().lock();
        if let Err(error) = write!(err, "{clear}{line}") {
            tracing::debug!(%error, ticker = redraw_error_label, "progress redraw write error");
        }
        let _ = err.flush(); // LAW10: unused-binding marker; no runtime effect, not a fallback
        drop(err);
        if done.load(Ordering::Relaxed) {
            break;
        }
        for _ in 0..9 {
            if done.load(Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(tick / 9);
        }
        frame = frame.wrapping_add(1);
    }
    let mut err = std::io::stderr().lock();
    let _ = write!(err, "{}", terminal_clear_line_prefix(true)); // LAW10: unused-binding marker; no runtime effect, not a fallback
    let _ = err.flush(); // LAW10: unused-binding marker; no runtime effect, not a fallback
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
pub(crate) fn progress_ticker(done: Arc<AtomicBool>, started: Instant) {
    terminal_ticker_loop(done, started, "scan", |elapsed, frame, color| {
        let scanned = crate::SCANNED_CHUNKS.load(std::sync::atomic::Ordering::Relaxed);
        let total = crate::TOTAL_CHUNKS.load(std::sync::atomic::Ordering::Relaxed);
        let findings = crate::FINDINGS_COUNT.load(std::sync::atomic::Ordering::Relaxed);
        render_ticker_line(scanned, total, findings, elapsed, frame, color)
    });
}

/// Live verification ticker. Verification happens after scan chunks have
/// completed, so the scan ticker is no longer alive. This keeps `--verify`
/// operator-visible during the network phase instead of going quiet between
/// scanning and the final report.
pub(crate) fn verification_ticker(done: Arc<AtomicBool>, started: Instant, total: usize) {
    terminal_ticker_loop(done, started, "verification", |elapsed, frame, color| {
        render_verification_ticker_line(total, elapsed, frame, color)
    });
}

/// Live reporting ticker. Report serialization and atomic-file fsync happen
/// after scanning/verification tickers have stopped. Keep that blocking phase
/// visible on interactive terminals without writing anything to stdout.
pub(crate) fn reporting_ticker(done: Arc<AtomicBool>, started: Instant, total: usize) {
    terminal_ticker_loop(done, started, "reporting", |elapsed, frame, color| {
        render_reporting_ticker_line(total, elapsed, frame, color)
    });
}

pub(crate) fn report_skip_summary(ansi: bool) {
    // Snapshot every coverage-gap counter once, then render each non-zero
    // category from the ONE canonical set this human summary and the structured
    // SARIF/HTML report share (`crate::reporting::CoverageGapKind`). A category
    // can therefore never appear on one surface and not the other — a gap
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
    let payload = serde_json::json!({
        "dogfood": {
            "example_suppressions_total": suppressed,
            "events": events,
        }
    });
    eprintln!("{payload}");
}

#[cfg(test)]
mod tests;
