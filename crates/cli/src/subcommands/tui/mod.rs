//! `keyhog tui`: live-scan dashboard.
//!
//! Spawns a worker thread that walks the target path, scans each file
//! against the embedded detector corpus, streams findings to the UI
//! over an mpsc channel and updates shared atomic counters. The
//! foreground thread runs a ratatui event loop polling keyboard at
//! 50 ms and redrawing at the same cadence. Both shut down cleanly:
//!   - `q` / `Esc` on the keyboard sets the cancel flag, the worker
//!     observes it on the next file and exits.
//!   - scan completion sets a `done` flag, the UI banner switches to
//!     "complete" and the user presses any key to leave the TUI.

mod render;
mod worker;

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use keyhog_core::{DedupedMatch, Severity};
use keyhog_scanner::engine::CompiledScanner;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use crate::args::TuiArgs;

/// Compact event the worker sends to the UI. We deliberately do NOT
/// send the full `RawMatch` (it carries Arc<str>s + companions); the
/// UI only needs to render severity + redacted credential + location,
/// which keeps the channel cheap and avoids leaking the live secret
/// past the redaction call into TUI state.
#[derive(Clone)]
struct FindingEvent {
    severity: Severity,
    service: String,
    detector_id: String,
    path: String,
    line: Option<usize>,
    redacted: String,
}

impl From<&DedupedMatch> for FindingEvent {
    fn from(m: &DedupedMatch) -> Self {
        Self {
            severity: m.severity,
            service: m.service.to_string(),
            detector_id: m.detector_id.to_string(),
            path: m
                .primary_location
                .file_path
                .as_deref()
                .map(str::to_owned)
                .unwrap_or_else(|| "<stdin>".to_string()),
            line: m.primary_location.line,
            redacted: keyhog_core::redact(&m.credential).into_owned(),
        }
    }
}

/// Shared mutable counters between worker and UI. Reads on the UI side
/// are `Relaxed` because we draw at 50 ms and a stale read by one
/// frame is fine.
struct Counters {
    files_total: AtomicUsize,
    files_done: AtomicUsize,
    bytes_done: AtomicU64,
    findings_total: AtomicUsize,
    done: AtomicBool,
    /// Path of the file the worker is currently scanning. Lock-free
    /// reads use `parking_lot::Mutex<String>`-equivalent semantics via
    /// `std::sync::RwLock`; the UI draws this in the banner so the
    /// viewer sees scan progress through the tree even on tiny demo
    /// corpora where chunk counts move too fast to read.
    current_file: std::sync::RwLock<String>,
}

pub fn run(args: TuiArgs) -> Result<ExitCode> {
    let target = args
        .path
        .canonicalize()
        .with_context(|| format!("resolving scan target {}", args.path.display()))?;
    if !target.exists() {
        anyhow::bail!("scan target does not exist: {}", target.display());
    }

    let mut detectors = Vec::new();
    for (path, toml_str) in keyhog_core::embedded_detector_tomls() {
        match keyhog_core::load_detectors_from_str(toml_str) {
            Ok(mut ds) => detectors.append(&mut ds),
            Err(e) => {
                tracing::debug!(detector = %path, error = %e, "skipping malformed embedded detector");
            }
        }
    }
    if detectors.is_empty() {
        anyhow::bail!("embedded detector corpus is empty (build-time issue)");
    }
    let scanner = CompiledScanner::compile(detectors).context("compiling scanner")?;
    let scanner = Arc::new(scanner);

    let counters = Arc::new(Counters {
        files_total: AtomicUsize::new(0),
        files_done: AtomicUsize::new(0),
        bytes_done: AtomicU64::new(0),
        findings_total: AtomicUsize::new(0),
        done: AtomicBool::new(false),
        current_file: std::sync::RwLock::new(String::new()),
    });
    let cancel = Arc::new(AtomicBool::new(false));

    let (sender, receiver) = channel::<FindingEvent>();
    let worker_counters = Arc::clone(&counters);
    let worker_scanner = Arc::clone(&scanner);
    let worker_cancel = Arc::clone(&cancel);
    let worker_target = target.clone();
    let worker_max_files = args.max_files;
    let worker_throttle = args.throttle_ms;
    let worker = std::thread::spawn(move || {
        worker::scan_worker(
            worker_target,
            worker_scanner,
            worker_counters,
            worker_cancel,
            sender,
            worker_max_files,
            worker_throttle,
        );
    });

    let outcome = run_ui(
        target,
        scanner,
        counters,
        cancel,
        receiver,
        args.feed_depth.max(1),
    );

    let _ = worker.join();
    outcome
}

fn run_ui(
    target: PathBuf,
    scanner: Arc<CompiledScanner>,
    counters: Arc<Counters>,
    cancel: Arc<AtomicBool>,
    receiver: Receiver<FindingEvent>,
    feed_depth: usize,
) -> Result<ExitCode> {
    // Install a panic hook that restores the terminal before unwinding.
    // Without this, a panic mid-loop leaves the user looking at a frozen
    // alt screen with raw mode still on (no keyboard echo, no prompt,
    // scrollback hidden). The hook only chains in once per process via
    // a OnceLock guard so the regular default-panic-hook output still
    // happens for tests / non-TUI panics.
    static TUI_PANIC_HOOK_INSTALLED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if TUI_PANIC_HOOK_INSTALLED.set(()).is_ok() {
        let prior = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = disable_raw_mode();
            let _ = execute!(io::stdout(), LeaveAlternateScreen);
            prior(info);
        }));
    }

    enable_raw_mode().context("entering raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("entering alt screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("creating terminal")?;

    let backend_label = scanner
        .gpu_backend_label()
        .map(str::to_owned)
        .unwrap_or_else(|| "cpu".to_string());
    let preferred_backend = scanner.preferred_backend_label().to_string();
    let pattern_count = scanner.pattern_count();

    let started = Instant::now();
    // Once the scan completes the dashboard is STATIC ("press any key to
    // exit"). Freeze the elapsed clock at the scan's real duration instead of
    // letting it tick up forever, and stop the 50 ms redraw/poll spin so the
    // idle dashboard sits near-0% CPU rather than busy-looping. `needs_redraw`
    // gates the post-scan repaint to actual changes (a resize); while scanning
    // we always repaint because the counters + elapsed advance every frame.
    let mut frozen_elapsed: Option<Duration> = None;
    let mut findings_feed: std::collections::VecDeque<FindingEvent> =
        std::collections::VecDeque::with_capacity(feed_depth);
    let mut needs_redraw = true;

    let result: Result<()> = loop {
        while let Ok(ev) = receiver.try_recv() {
            if findings_feed.len() >= feed_depth {
                findings_feed.pop_front();
            }
            findings_feed.push_back(ev);
            needs_redraw = true;
        }

        let done = counters.done.load(Ordering::Relaxed);
        if done && frozen_elapsed.is_none() {
            // Scan just finished: snapshot the final elapsed ONCE and force a
            // last repaint so the frozen state is painted.
            frozen_elapsed = Some(started.elapsed());
            needs_redraw = true;
        }
        let elapsed = frozen_elapsed.unwrap_or_else(|| started.elapsed());

        if !done || needs_redraw {
            if let Err(e) = terminal.draw(|frame| {
                render::render(
                    frame,
                    &target,
                    &backend_label,
                    &preferred_backend,
                    pattern_count,
                    &counters,
                    &findings_feed,
                    elapsed,
                    done,
                );
            }) {
                break Err(anyhow::Error::new(e).context("drawing TUI frame"));
            }
            needs_redraw = false;
        }

        // Poll cadence: tight (50 ms) while scanning for live progress; relaxed
        // (500 ms) once the scan is done so the idle "press any key" dashboard
        // doesn't burn CPU. A keypress or resize returns from `poll` the instant
        // it arrives regardless of the timeout, so responsiveness is unchanged.
        let poll_timeout = if done {
            Duration::from_millis(500)
        } else {
            Duration::from_millis(50)
        };
        if event::poll(poll_timeout).context("polling keyboard")? {
            match event::read().context("reading terminal event")? {
                Event::Key(k) => {
                    if k.kind == KeyEventKind::Press
                        && (matches!(k.code, KeyCode::Char('q') | KeyCode::Esc)
                            || (k.code == KeyCode::Char('c')
                                && k.modifiers.contains(KeyModifiers::CONTROL))
                            || done)
                    {
                        cancel.store(true, Ordering::Relaxed);
                        break Ok(());
                    }
                }
                // A resize invalidates the frozen frame; repaint next iteration.
                Event::Resize(_, _) => needs_redraw = true,
                _ => {}
            }
        }
    };

    disable_raw_mode().ok();
    let mut stdout = io::stdout();
    execute!(stdout, LeaveAlternateScreen).ok();
    stdout.flush().ok();

    result.map(|_| {
        if counters.findings_total.load(Ordering::Relaxed) > 0 {
            ExitCode::from(1)
        } else {
            ExitCode::SUCCESS
        }
    })
}
