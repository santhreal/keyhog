//! Daemon-resident filesystem watcher for guard roots.
//!
//! This module manages native filesystem watchers for registered guard
//! roots. It uses the `notify` crate (inotify on Linux, FSEvents on
//! macOS, ReadDirectoryChangesW on Windows) to receive change events
//! without polling.
//!
//! The watcher is advisory: it provides early feedback while files
//! change. It never authorizes a commit by itself. A commit is allowed
//! only after the exact staged-object transaction proves the content
//! is clean.
//!
//! ## Subscribe-first
//!
//! The watcher is registered BEFORE the baseline walk starts, so events
//! that arrive during the walk are buffered and replayed after the walk
//! completes. This closes the race between watcher registration and
//! scanning existing bytes.

use keyhog_sources::guard::{EventBuffer, GuardEvent, GuardReconciliationConfig};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;

/// Active watcher backend kind classified with performance characteristics (Row 123).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum GuardWatcherBackendKind {
    /// Linux inotify (kernel event driven).
    Inotify,
    /// macOS FSEvents (event stream).
    Fsevent,
    /// BSD/macOS kqueue (kernel queue event driven).
    Kqueue,
    /// Windows ReadDirectoryChangesW (asynchronous directory change port).
    ReadDirectoryChangesWatcher,
    /// Polling fallback watcher.
    PollWatcher,
    /// Null/no-op watcher (for tests or unsupported environments).
    NullWatcher,
    /// Explicitly disabled watcher.
    Disabled,
    /// Test channel simulation watcher.
    CustomTest,
}

impl GuardWatcherBackendKind {
    /// Human-readable label for daemon status and telemetry.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Inotify => "inotify",
            Self::Fsevent => "fsevent",
            Self::Kqueue => "kqueue",
            Self::ReadDirectoryChangesWatcher => "read-directory-changes",
            Self::PollWatcher => "poll",
            Self::NullWatcher => "null",
            Self::Disabled => "disabled",
            Self::CustomTest => "channel-test",
        }
    }

    /// Whether this backend uses native OS event notifications rather than interval polling.
    #[must_use]
    pub const fn is_native(self) -> bool {
        match self {
            Self::Inotify | Self::Fsevent | Self::Kqueue | Self::ReadDirectoryChangesWatcher => {
                true
            }
            Self::PollWatcher | Self::NullWatcher | Self::Disabled | Self::CustomTest => false,
        }
    }

    /// Latency tier classification.
    #[must_use]
    pub const fn latency_tier(self) -> &'static str {
        match self {
            Self::Inotify | Self::Kqueue => "sub-millisecond",
            Self::Fsevent | Self::ReadDirectoryChangesWatcher => "event-driven",
            Self::PollWatcher => "polling",
            Self::NullWatcher | Self::Disabled => "unmonitored",
            Self::CustomTest => "in-memory",
        }
    }

    /// Declared expected latency bound in milliseconds for totality testing.
    #[must_use]
    pub const fn expected_latency_bound_ms(self) -> u64 {
        match self {
            Self::Inotify | Self::Kqueue => 50,
            Self::Fsevent | Self::ReadDirectoryChangesWatcher => 250,
            Self::PollWatcher => 30_000,
            Self::NullWatcher | Self::Disabled => 0,
            Self::CustomTest => 10,
        }
    }

    /// Map from `notify::WatcherKind` to classified `GuardWatcherBackendKind`.
    #[must_use]
    pub fn from_notify_kind(kind: notify::WatcherKind) -> Self {
        match kind {
            notify::WatcherKind::Inotify => Self::Inotify,
            notify::WatcherKind::Fsevent => Self::Fsevent,
            notify::WatcherKind::Kqueue => Self::Kqueue,
            notify::WatcherKind::ReadDirectoryChangesWatcher => Self::ReadDirectoryChangesWatcher,
            notify::WatcherKind::PollWatcher => Self::PollWatcher,
            notify::WatcherKind::NullWatcher => Self::NullWatcher,
            _ => Self::PollWatcher,
        }
    }

    /// Enumerate all known backend kinds for exhaustive runtime classification assertions.
    #[must_use]
    pub const fn all_kinds() -> &'static [Self] {
        &[
            Self::Inotify,
            Self::Fsevent,
            Self::Kqueue,
            Self::ReadDirectoryChangesWatcher,
            Self::PollWatcher,
            Self::NullWatcher,
            Self::Disabled,
            Self::CustomTest,
        ]
    }
}

/// Unified wrapper over native recommended, polling, or null watchers.
enum ActiveWatcherHandle {
    Recommended(RecommendedWatcher),
    Poll(notify::PollWatcher),
    Null(notify::NullWatcher),
}

impl ActiveWatcherHandle {
    fn watch(&mut self, path: &std::path::Path, mode: RecursiveMode) -> notify::Result<()> {
        match self {
            Self::Recommended(w) => w.watch(path, mode),
            Self::Poll(w) => w.watch(path, mode),
            Self::Null(w) => w.watch(path, mode),
        }
    }

    fn unwatch(&mut self, path: &std::path::Path) -> notify::Result<()> {
        match self {
            Self::Recommended(w) => w.unwatch(path),
            Self::Poll(w) => w.unwatch(path),
            Self::Null(w) => w.unwatch(path),
        }
    }
}

/// One watched root and its event buffer.
struct WatchedRoot {
    /// Bounded event buffer with monotonic sequence.
    buffer: Arc<Mutex<EventBuffer>>,
}

/// Manages filesystem watchers for all guard roots.
pub struct GuardWatcher {
    /// The native watcher handle. One watcher serves all roots.
    /// `None` when the platform watcher could not be created or is disabled.
    watcher: Option<ActiveWatcherHandle>,
    /// Classified active watcher backend kind.
    backend_kind: GuardWatcherBackendKind,
    /// Polling interval in milliseconds if using a polling watcher.
    poll_interval_ms: Option<u64>,
    /// Channel receiver for events from the native watcher.
    rx: mpsc::Receiver<notify::Result<notify::Event>>,
    /// Tracked roots: canonical path -> watched root state.
    roots: HashMap<PathBuf, WatchedRoot>,
    /// Reconciliation config (bounds for subtree reconciliation).
    config: GuardReconciliationConfig,
}

impl GuardWatcher {
    /// Create a new guard watcher with the given config.
    pub fn new(config: GuardReconciliationConfig) -> Result<Self, String> {
        let (tx, rx) = mpsc::channel::<notify::Result<notify::Event>>();
        let watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            let _ = tx.send(res);
        })
        .map_err(|e| format!("failed to create filesystem watcher: {}", e))?;
        let backend_kind = GuardWatcherBackendKind::from_notify_kind(RecommendedWatcher::kind());
        let poll_interval_ms = if backend_kind == GuardWatcherBackendKind::PollWatcher {
            Some(2000)
        } else {
            None
        };
        Ok(Self {
            watcher: Some(ActiveWatcherHandle::Recommended(watcher)),
            backend_kind,
            poll_interval_ms,
            rx,
            roots: HashMap::new(),
            config,
        })
    }

    /// Create a polling watcher with an explicit interval.
    pub fn new_polling(
        config: GuardReconciliationConfig,
        poll_interval: std::time::Duration,
    ) -> Result<Self, String> {
        let (tx, rx) = mpsc::channel::<notify::Result<notify::Event>>();
        let notify_config = notify::Config::default().with_poll_interval(poll_interval);
        let watcher = notify::PollWatcher::new(
            move |res: notify::Result<notify::Event>| {
                let _ = tx.send(res);
            },
            notify_config,
        )
        .map_err(|e| format!("failed to create polling filesystem watcher: {e}"))?;
        Ok(Self {
            watcher: Some(ActiveWatcherHandle::Poll(watcher)),
            backend_kind: GuardWatcherBackendKind::PollWatcher,
            poll_interval_ms: Some(poll_interval.as_millis() as u64),
            rx,
            roots: HashMap::new(),
            config,
        })
    }

    /// Create a null/no-op watcher.
    pub fn new_null(config: GuardReconciliationConfig) -> Result<Self, String> {
        let (_tx, rx) = mpsc::channel::<notify::Result<notify::Event>>();
        let watcher = notify::NullWatcher;
        Ok(Self {
            watcher: Some(ActiveWatcherHandle::Null(watcher)),
            backend_kind: GuardWatcherBackendKind::NullWatcher,
            poll_interval_ms: None,
            rx,
            roots: HashMap::new(),
            config,
        })
    }

    /// Create a disabled watcher that never produces events. Guard
    /// still works via commit transactions; it just loses advisory
    /// filesystem events.
    pub fn new_disabled() -> Self {
        let (_tx, rx) = mpsc::channel::<notify::Result<notify::Event>>();
        Self {
            watcher: None,
            backend_kind: GuardWatcherBackendKind::Disabled,
            poll_interval_ms: None,
            rx,
            roots: HashMap::new(),
            config: GuardReconciliationConfig::default(),
        }
    }

    /// Create a guard watcher connected to a custom event channel.
    /// Used for deterministic simulation and tests without native watcher hooks.
    pub fn new_with_channel(
        config: GuardReconciliationConfig,
    ) -> (Self, mpsc::Sender<notify::Result<notify::Event>>) {
        let (tx, rx) = mpsc::channel::<notify::Result<notify::Event>>();
        (
            Self {
                watcher: None,
                backend_kind: GuardWatcherBackendKind::CustomTest,
                poll_interval_ms: None,
                rx,
                roots: HashMap::new(),
                config,
            },
            tx,
        )
    }

    /// Returns the active watcher backend kind.
    #[must_use]
    pub fn backend_kind(&self) -> GuardWatcherBackendKind {
        self.backend_kind
    }

    /// Returns the active watcher backend label.
    #[must_use]
    pub fn backend_label(&self) -> &'static str {
        self.backend_kind.label()
    }

    /// Returns the active watcher latency tier.
    #[must_use]
    pub fn latency_tier(&self) -> &'static str {
        self.backend_kind.latency_tier()
    }

    /// Returns the polling interval in milliseconds if using a polling watcher.
    #[must_use]
    pub fn poll_interval_ms(&self) -> Option<u64> {
        self.poll_interval_ms
    }

    /// Returns the configured coalesce window in milliseconds.
    pub fn coalesce_window_ms(&self) -> u64 {
        self.config.coalesce_window_ms
    }

    /// Register a new root for watching. The watcher is started before
    /// the baseline walk so events during the walk are captured.
    pub fn add_root(&mut self, path: PathBuf) -> Result<(), String> {
        if self.roots.contains_key(&path) {
            return Err(format!("root already watched: {}", path.display()));
        }
        if let Some(ref mut watcher) = self.watcher {
            watcher
                .watch(&path, RecursiveMode::Recursive)
                .map_err(|e| {
                    format!(
                        "failed to watch {}: {}; on Linux raise fs.inotify.max_user_watches",
                        path.display(),
                        e
                    )
                })?;
        }
        let buffer = Arc::new(Mutex::new(EventBuffer::new(
            self.config.max_pending_events_per_root,
        )));
        self.roots.insert(path, WatchedRoot { buffer });
        Ok(())
    }

    /// Remove a root from watching.
    pub fn remove_root(&mut self, path: &std::path::Path) {
        if self.roots.remove(path).is_some() {
            if let Some(ref mut watcher) = self.watcher {
                let _ = watcher.unwatch(path);
            }
        }
    }
    /// Poll for events from the native watcher. Returns normalized
    /// guard events grouped by root path. Non-blocking. Drains the
    /// per-root buffer as events are handed to the caller, so the
    /// buffer does not grow unbounded. If the buffer overflowed, a
    /// single `ReconcileSubtree` event is emitted for that root and
    /// the overflow flag is cleared.
    pub fn poll_events(&self) -> Vec<(PathBuf, Vec<GuardEvent>)> {
        let mut results: HashMap<PathBuf, Vec<GuardEvent>> = HashMap::new();
        loop {
            match self.rx.try_recv() {
                Ok(Ok(event)) => {
                    if let Some(path) = event.paths.first() {
                        if let Some(root) = self.find_root_for_path(path) {
                            let guard_events = normalize_notify_event(&event);
                            if let Some(buffer) = self.roots.get(&root) {
                                let mut buf = buffer.buffer.lock();
                                for ge in &guard_events {
                                    buf.push(ge.clone());
                                }
                            }
                        }
                    }
                }
                Ok(Err(_)) => {
                    for root in self.roots.keys() {
                        results
                            .entry(root.clone())
                            .or_default()
                            .push(GuardEvent::ReconcileSubtree(root.clone()));
                    }
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => break,
            }
        }
        // Drain each root's buffer and check for overflow. If overflowed,
        // emit a ReconcileSubtree event and reset the overflow flag so
        // the buffer can accept new events after reconciliation.
        for (root, watched) in &self.roots {
            let mut buf = watched.buffer.lock();
            if buf.overflowed() {
                results
                    .entry(root.clone())
                    .or_default()
                    .push(GuardEvent::ReconcileSubtree(root.clone()));
                buf.drain_and_reset();
            } else {
                let buffered: Vec<GuardEvent> = buf.drain().into_iter().map(|(_, ge)| ge).collect();
                if !buffered.is_empty() {
                    results.entry(root.clone()).or_default().extend(buffered);
                }
            }
        }
        results.into_iter().collect()
    }

    /// Find which registered root a path belongs to.
    fn find_root_for_path(&self, path: &std::path::Path) -> Option<PathBuf> {
        for root in self.roots.keys() {
            if path.starts_with(root) {
                return Some(root.clone());
            }
        }
        None
    }

    /// Number of watched roots.
    #[allow(dead_code)]
    pub fn root_count(&self) -> usize {
        self.roots.len()
    }

    #[allow(dead_code)]
    /// Whether any roots are watched.
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// Number of pending events in the buffer for a root.
    pub fn pending_event_count(&self, root: &std::path::Path) -> usize {
        self.roots
            .get(root)
            .map(|r| r.buffer.lock().len())
            .unwrap_or(0)
    }
}

/// Convert a notify::Event into normalized GuardEvent(s).
fn normalize_notify_event(event: &notify::Event) -> Vec<GuardEvent> {
    let path = event.paths.first().cloned().unwrap_or_default();
    match event.kind {
        EventKind::Create(_) => vec![GuardEvent::Create(path)],
        EventKind::Modify(_) => vec![GuardEvent::Modify(path)],
        EventKind::Remove(_) => vec![GuardEvent::Remove(path)],
        _ => {
            if !event.paths.is_empty() {
                vec![GuardEvent::Modify(path)]
            } else {
                Vec::new()
            }
        }
    }
}
#[cfg(test)]
#[path = "../../tests/unit/daemon_guard_watcher.rs"]
mod tests;
