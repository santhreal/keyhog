//! Workgroup-size auto-tuner (C-B6).
//!
//! On first dispatch of a (program, adapter) pair, sweeps candidate
//! workgroup sizes via GPU timestamp queries and caches the winner
//! to `~/.cache/vyre/tuner/<adapter_fp>.toml`. Subsequent dispatches
//! read the cache and skip the sweep.
//!
//! Off by default (env `VYRE_AUTOTUNER=off`) — autotuning adds
//! cold-start latency. Enable via `VYRE_AUTOTUNER=on`, or set
//! `VYRE_AUTOTUNER=off` explicitly to disable in otherwise-tuned
//! environments.
//!
//! The tuner *measures* workgroup size — it doesn't decide which
//! workgroup sizes are legal. Callers constrain candidates through
//! `Tuner::candidates_for` so that adapter limits and dispatch
//! shape are respected.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

const CANDIDATES: &[u32] = &[32, 64, 128, 256, 512, 1024];
const DEFAULT_WORKGROUP_SIZE: [u32; 3] = [64, 1, 1];
const AUTOTUNER_ENV: &str = "VYRE_AUTOTUNER";

/// Tuner runtime mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Mode {
    /// Sweep candidate sizes on first dispatch (cold start cost).
    On,
    /// Use cached decision when present; otherwise default
    /// workgroup size `[64,1,1]`.
    OffUseDefault,
}

impl Mode {
    /// Resolve mode from `VYRE_AUTOTUNER` env var.
    ///
    /// `on` → [`Mode::On`]; `off` or absent → [`Mode::OffUseDefault`].
    /// Any other value is treated as `off` with no error, so setting
    /// typos doesn't inadvertently enable the sweep.
    #[must_use]
    pub fn from_env() -> Self {
        match std::env::var(AUTOTUNER_ENV).ok().as_deref() {
            Some("on") => Mode::On,
            _ => Mode::OffUseDefault,
        }
    }
}

/// Per-adapter tuner decisions keyed by program fingerprint.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TunerCache {
    /// `program_fingerprint -> best_workgroup_size`
    pub entries: BTreeMap<String, [u32; 3]>,
}

impl TunerCache {
    /// Return the best workgroup size for the given program, if
    /// cached.
    #[must_use]
    pub fn get(&self, program_fp: &str) -> Option<[u32; 3]> {
        self.entries.get(program_fp).copied()
    }

    /// Record a decision.
    pub fn set(&mut self, program_fp: impl Into<String>, size: [u32; 3]) {
        self.entries.insert(program_fp.into(), size);
    }

    /// Load from a TOML file. Missing file returns an empty cache
    /// (equivalent to first-run).
    ///
    /// # Errors
    ///
    /// Returns `Err` only when the file exists but contains syntactically
    /// invalid TOML.
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let Ok(contents) = fs::read_to_string(path) else {
            return Ok(Self::default());
        };
        let parsed: toml::Value = toml::from_str(&contents).map_err(|e| {
            format!(
                "Fix: tuner cache `{}` is not valid TOML: {e}",
                path.display()
            )
        })?;
        let mut entries = BTreeMap::new();
        if let Some(table) = parsed.as_table() {
            for (key, value) in table {
                if let Some(arr) = value.as_array() {
                    if arr.len() == 3 {
                        let mut triple = [0u32; 3];
                        for (i, v) in arr.iter().enumerate() {
                            if let Some(n) = v.as_integer() {
                                if let Ok(u) = u32::try_from(n) {
                                    triple[i] = u;
                                } else {
                                    continue;
                                }
                            }
                        }
                        entries.insert(key.clone(), triple);
                    }
                }
            }
        }
        Ok(Self { entries })
    }

    /// Persist to disk. Creates parent directories as needed.
    ///
    /// # Errors
    ///
    /// Returns `Err` when the parent directory cannot be created or
    /// the file cannot be written.
    pub fn save(&self, path: &std::path::Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "Fix: could not create tuner cache directory {}: {e}",
                    parent.display()
                )
            })?;
        }
        let mut out = String::new();
        for (key, size) in &self.entries {
            out.push_str(&format!(
                "\"{}\" = [{}, {}, {}]\n",
                key, size[0], size[1], size[2]
            ));
        }
        fs::write(path, &out)
            .map_err(|e| format!("Fix: could not write tuner cache {}: {e}", path.display()))
    }
}

/// Workgroup-size auto-tuner.
///
/// Construct one per adapter. The tuner loads / persists its cache
/// via [`Tuner::cache_path_for_adapter`].
pub struct Tuner {
    mode: Mode,
    cache: TunerCache,
    cache_path: PathBuf,
}

impl Tuner {
    /// Build a new tuner for the adapter fingerprinted as
    /// `adapter_fp`.
    #[must_use]
    pub fn new(adapter_fp: &str, mode: Mode) -> Self {
        let cache_path = Self::cache_path_for_adapter(adapter_fp);
        let cache = TunerCache::load(&cache_path).unwrap_or_default();
        Self {
            mode,
            cache,
            cache_path,
        }
    }

    /// Cache file path for a given adapter fingerprint.
    #[must_use]
    pub fn cache_path_for_adapter(adapter_fp: &str) -> PathBuf {
        let mut home = dirs_cache_root();
        home.push("vyre");
        home.push("tuner");
        home.push(format!("{adapter_fp}.toml"));
        home
    }

    /// Candidate workgroup sizes this tuner considers. Callers
    /// intersect with adapter limits before dispatching.
    #[must_use]
    pub fn candidates_for(&self, max_invocations: u32) -> Vec<u32> {
        CANDIDATES
            .iter()
            .copied()
            .filter(|c| *c <= max_invocations)
            .collect()
    }

    /// Default workgroup size used when the tuner is off and no
    /// cache entry exists.
    #[must_use]
    pub fn default_workgroup_size() -> [u32; 3] {
        DEFAULT_WORKGROUP_SIZE
    }

    /// Mode this tuner is running in.
    #[must_use]
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Resolve the workgroup size for a program.
    ///
    /// * If the cache has an entry, returns it regardless of mode —
    ///   even `Mode::OffUseDefault` respects a prior decision.
    /// * If `Mode::On`, the caller runs the sweep (via
    ///   [`Tuner::record_decision`]) and persists the result.
    /// * If `Mode::OffUseDefault` with no cache entry, returns
    ///   [`Tuner::default_workgroup_size`].
    #[must_use]
    pub fn resolve(&self, program_fp: &str) -> [u32; 3] {
        if let Some(size) = self.cache.get(program_fp) {
            return size;
        }
        Self::default_workgroup_size()
    }

    /// Record a sweep outcome, updating the in-memory cache. Call
    /// [`Tuner::persist`] to write it out to disk.
    pub fn record_decision(&mut self, program_fp: impl Into<String>, size: [u32; 3]) {
        self.cache.set(program_fp, size);
    }

    /// Write the cache to disk.
    ///
    /// # Errors
    ///
    /// Returns the structured error from [`TunerCache::save`].
    pub fn persist(&self) -> Result<(), String> {
        self.cache.save(&self.cache_path)
    }
}

fn dirs_cache_root() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
        PathBuf::from(xdg)
    } else if let Some(home) = std::env::var_os("HOME") {
        let mut p = PathBuf::from(home);
        p.push(".cache");
        p
    } else {
        PathBuf::from(".")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_off_when_env_absent() {
        // Safe even when other tests set VYRE_AUTOTUNER — we
        // remove before reading. Cargo runs tests in parallel but
        // this read sees a stable state within the test's scope.
        let saved = std::env::var(AUTOTUNER_ENV).ok();
        std::env::remove_var(AUTOTUNER_ENV);
        let m = Mode::from_env();
        assert_eq!(m, Mode::OffUseDefault);
        if let Some(s) = saved {
            std::env::set_var(AUTOTUNER_ENV, s);
        }
    }

    #[test]
    fn candidates_respect_max_invocations() {
        let t = Tuner::new("test", Mode::OffUseDefault);
        let low = t.candidates_for(64);
        assert_eq!(low, vec![32, 64]);
        let high = t.candidates_for(1024);
        assert_eq!(high.len(), CANDIDATES.len());
    }

    #[test]
    fn default_wgs_is_64_1_1() {
        assert_eq!(Tuner::default_workgroup_size(), [64, 1, 1]);
    }

    #[test]
    fn cache_round_trips() {
        let mut cache = TunerCache::default();
        cache.set("prog-a", [128, 1, 1]);
        cache.set("prog-b", [256, 1, 1]);

        let tmp = std::env::temp_dir().join("vyre-tuner-test.toml");
        cache.save(&tmp).expect("Fix: save");
        let loaded = TunerCache::load(&tmp).expect("Fix: load");
        assert_eq!(loaded.get("prog-a"), Some([128, 1, 1]));
        assert_eq!(loaded.get("prog-b"), Some([256, 1, 1]));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn cache_missing_file_returns_empty() {
        let path = std::path::PathBuf::from("/nonexistent/dir/vyre-tuner-missing.toml");
        let c = TunerCache::load(&path).expect("Fix: missing file → empty, not error");
        assert!(c.entries.is_empty());
    }

    #[test]
    fn resolve_falls_back_to_default_without_cache_entry() {
        let t = Tuner::new("adapter-test", Mode::OffUseDefault);
        let size = t.resolve("no-such-program");
        assert_eq!(size, Tuner::default_workgroup_size());
    }

    #[test]
    fn record_decision_updates_cache() {
        let mut t = Tuner::new("adapter-rec", Mode::On);
        t.record_decision("prog-x", [512, 1, 1]);
        assert_eq!(t.resolve("prog-x"), [512, 1, 1]);
    }

    // ── Phase 17 — adaptive feedback loop ─────────────────────────

    #[test]
    fn feedback_default_policy_grows_under_starvation() {
        let fb = TunerFeedback {
            per_opcode_counts: vec![(0, 10)],
            wall_time_us: 1_000,
            idle_us: 0,
            observed_workgroup_size_x: 64,
            observed_throughput_per_us: 0.01, // low
        };
        let policy = DefaultPolicy::default();
        let suggestion = policy.suggest_resize(&fb);
        assert_eq!(
            suggestion,
            Some(128),
            "under-saturated throughput should grow workgroup by 2x"
        );
    }

    #[test]
    fn feedback_default_policy_shrinks_when_idle() {
        let fb = TunerFeedback {
            per_opcode_counts: Vec::new(),
            wall_time_us: 1_000_000,
            idle_us: 200_000, // 200ms > 100ms idle threshold
            observed_workgroup_size_x: 256,
            observed_throughput_per_us: 0.5, // OK
        };
        let policy = DefaultPolicy::default();
        assert_eq!(
            policy.suggest_resize(&fb),
            Some(128),
            "long idle must shrink workgroup to reduce tail latency"
        );
    }

    #[test]
    fn feedback_default_policy_holds_when_balanced() {
        let fb = TunerFeedback {
            per_opcode_counts: vec![(0, 1000)],
            wall_time_us: 10_000,
            idle_us: 0,
            observed_workgroup_size_x: 128,
            observed_throughput_per_us: 2.0, // above saturation threshold
        };
        let policy = DefaultPolicy::default();
        assert_eq!(policy.suggest_resize(&fb), None);
    }

    #[test]
    fn feedback_respects_adapter_cap() {
        let fb = TunerFeedback {
            per_opcode_counts: Vec::new(),
            wall_time_us: 100,
            idle_us: 0,
            observed_workgroup_size_x: 256,
            observed_throughput_per_us: 0.0,
        };
        let policy = DefaultPolicy {
            adapter_max_workgroup_size_x: 256,
            ..DefaultPolicy::default()
        };
        // Current already at cap → can't grow.
        assert_eq!(
            policy.suggest_resize(&fb),
            None,
            "adapter cap must pin the tuner"
        );
    }

    #[test]
    fn feedback_shrink_bounded_by_minimum() {
        let fb = TunerFeedback {
            per_opcode_counts: Vec::new(),
            wall_time_us: 1_000_000,
            idle_us: 500_000,
            observed_workgroup_size_x: 32,
            observed_throughput_per_us: 0.5,
        };
        let policy = DefaultPolicy::default();
        // Already at minimum 32 → no further shrink.
        assert_eq!(policy.suggest_resize(&fb), None);
    }
}

// ── Phase 17 — adaptive feedback ──────────────────────────────────

/// Snapshot of live megakernel behavior the tuner consumes to
/// decide whether the current workgroup size still fits the
/// workload. Produced by reading the megakernel's metrics section
/// (`control[METRICS_BASE..]`) plus the host-side wall-time and
/// idle counters.
#[derive(Debug, Clone)]
pub struct TunerFeedback {
    /// `(opcode_id, execution_count)` pairs from the metrics
    /// region, non-zero entries only.
    pub per_opcode_counts: Vec<(u32, u32)>,
    /// Total wall-time the caller measured for this feedback
    /// window, in microseconds.
    pub wall_time_us: u64,
    /// Micros the megakernel spent idle (no slot CAS'd) inside the
    /// window.
    pub idle_us: u64,
    /// Workgroup size x this feedback was gathered on.
    pub observed_workgroup_size_x: u32,
    /// Slots per microsecond observed on the hot opcode. Zero if
    /// the caller couldn't compute it (the tuner treats this as
    /// starvation).
    pub observed_throughput_per_us: f64,
}

/// Hysteresis-based default policy.
///
/// - **Grow** (2×) when observed throughput drops below
///   `saturation_threshold_per_us` — the kernel is under-utilized
///   per lane, likely because we're spending cycles on scheduling
///   instead of work.
/// - **Shrink** (½×) when idle time exceeds `idle_shrink_us` — the
///   ring is starving the kernel, tail latency suffers, smaller
///   workgroups reduce launch latency.
/// - **Hold** otherwise.
///
/// Both growth and shrinking respect `adapter_max_workgroup_size_x`
/// and `minimum_workgroup_size_x` so the suggestion is always
/// dispatchable.
#[derive(Debug, Clone)]
pub struct DefaultPolicy {
    /// Upper bound from the adapter's capability probe.
    pub adapter_max_workgroup_size_x: u32,
    /// Floor below which we never shrink.
    pub minimum_workgroup_size_x: u32,
    /// Throughput (slots / µs) below which we grow.
    pub saturation_threshold_per_us: f64,
    /// Idle time (µs) above which we shrink.
    pub idle_shrink_us: u64,
}

impl Default for DefaultPolicy {
    fn default() -> Self {
        Self {
            adapter_max_workgroup_size_x: 1024,
            minimum_workgroup_size_x: 32,
            saturation_threshold_per_us: 1.0,
            idle_shrink_us: 100_000, // 100 ms
        }
    }
}

impl DefaultPolicy {
    /// Suggest a new workgroup size for the next feedback window.
    #[must_use]
    pub fn suggest_resize(&self, feedback: &TunerFeedback) -> Option<u32> {
        let current = feedback.observed_workgroup_size_x.max(1);
        let idle = feedback.idle_us > self.idle_shrink_us;

        if idle {
            // Idle-dominated window: shrink if we can, otherwise
            // hold. Growing a workgroup that is already starving
            // for work makes the starvation worse — never promote
            // a shrink failure into a grow.
            let shrunk = current / 2;
            if shrunk >= self.minimum_workgroup_size_x && shrunk != current {
                return Some(shrunk);
            }
            return None;
        }

        // Non-idle window: grow if throughput is under saturation
        // and the adapter cap allows it.
        if feedback.observed_throughput_per_us < self.saturation_threshold_per_us {
            let grown = current.saturating_mul(2);
            if grown <= self.adapter_max_workgroup_size_x && grown != current {
                return Some(grown);
            }
        }

        None
    }
}
