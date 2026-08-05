//! Live terminal progress: spinner frames, the determinate/indeterminate bar,
//! the three phase ticker lines, and the guard that owns a ticker thread.
//!
//! Separated from report rendering because this is the only part of reporting
//! that owns a thread, writes to the TTY on a timer, and has to be silent when
//! stdout is not a terminal. Report and summary rendering stay pure functions
//! of a finding slice.

use super::{finding_noun, secret_noun};
use crate::style::terminal_clear_line_prefix;
use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Instant;

// keyhog brand yellow (#ffd60a), severity heat colours and a dimmed rail, as
// 24-bit truecolor SGR. The escape literals live in `crate::style` (the one CLI
// file exempt from the no-raw-ANSI gate); imported here under the local `C_*`
// names the ticker/summary renderers use. Gated behind the ticker's `color`
// flag (TTY && !NO_COLOR) so piped/`NO_COLOR` output stays plain. Truecolor
// degrades gracefully to the nearest colour on 256/16-colour terminals; the
// layout is identical with or without colour.
use crate::style::{
    SEV_AMBER as C_AMBER, SEV_BOLD as C_BOLD, SEV_BRAND as C_BRAND, SEV_MUTED as C_MUTED,
    SEV_RAIL as C_RAIL, SEV_RESET as C_RESET,
};

/// Braille spinner cycle for every phase ticker (scan / verification / reporting).
/// Single owner so all three tickers spin identically; `frame % FRAMES.len()`
/// indexes it. Ten frames give a smooth 1/10-turn step per tick.
pub(crate) const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Progress/indeterminate bar cell width shared by every phase ticker, so the
/// determinate scan bar and the indeterminate warm-up/verify/report sweeps line
/// up to the same column. Single owner (the three tickers must not drift apart).
pub(crate) const BAR_WIDTH: usize = 22;

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

/// Indeterminate "warming up" sweep, a lit band that slides across a dim rail,
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
/// snapshot. Pure, so the exact layout is unit-testable and can be visually
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
///   spinner + an indeterminate sweep + the elapsed clock, never a frozen
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
#[cfg(feature = "verify")]
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
