//! Backend-neutral autotuner framework and cache metadata.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use vyre_foundation::ir::Program;

const CANDIDATES: &[u32] = &[32, 64, 128, 256, 512, 1024];
const AUTOTUNER_ENV: &str = "VYRE_AUTOTUNER";
const MAX_TUNER_CACHE_BYTES: u64 = 4 * 1024 * 1024;

/// Tuner runtime mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Mode {
    /// Sweep candidate sizes on first dispatch.
    On,
    /// Use cached decisions when present, otherwise the default workgroup.
    OffUseDefault,
}

impl Mode {
    /// Resolve mode from `VYRE_AUTOTUNER`.
    #[must_use]
    pub fn from_env() -> Self {
        match std::env::var(AUTOTUNER_ENV) {
            Ok(value) if value == "on" => Mode::On,
            Ok(value) if value == "off" || value == "default" => Mode::OffUseDefault,
            Ok(value) => panic!(
                "{AUTOTUNER_ENV}={value:?} is invalid. Fix: set VYRE_AUTOTUNER to `on`, `off`, or `default`, or unset it for the production default."
            ),
            Err(_) => Mode::OffUseDefault,
        }
    }
}

/// Backend timing hook used by the generic best-of-N framework.
pub trait BackendTimer {
    /// Error type returned by a concrete timing implementation.
    type Error;

    /// Measure one workgroup-size candidate and return elapsed nanoseconds.
    ///
    /// # Errors
    ///
    /// Returns the concrete backend timing error when the dispatch or timer
    /// instrumentation fails.
    fn measure_candidate_ns(
        &mut self,
        program: &Program,
        workgroup_size: [u32; 3],
    ) -> Result<u64, Self::Error>;
}

/// Per-adapter tuner decisions keyed by program fingerprint.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TunerCache {
    /// `program_fingerprint -> best_workgroup_size`.
    pub entries: BTreeMap<String, [u32; 3]>,
}

/// Static program shape used to disambiguate autotuner decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticProgramShape {
    /// Declared or overridden workgroup shape.
    pub workgroup_size: [u32; 3],
    /// Static workgroup-count override when known.
    pub workgroup_count: Option<[u32; 3]>,
    /// Static visible output byte count used by the dispatch.
    pub output_bytes: u64,
}

impl StaticProgramShape {
    /// Build a shape record from a program and caller-known launch facts.
    #[must_use]
    pub fn new(program: &Program, workgroup_count: Option<[u32; 3]>, output_bytes: u64) -> Self {
        Self {
            workgroup_size: program.workgroup_size(),
            workgroup_count,
            output_bytes,
        }
    }
}

/// Stable key for per-adapter workgroup autotuning decisions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TunerProgramKey(String);

impl TunerProgramKey {
    /// Build a key from the canonical program fingerprint plus static shape.
    #[must_use]
    pub fn from_program(program: &Program, shape: StaticProgramShape) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"vyre-driver-workgroup-tuner-v1\0program\0");
        hasher.update(&program.fingerprint());
        hasher.update(b"\0workgroup-size\0");
        for axis in shape.workgroup_size {
            hasher.update(&axis.to_le_bytes());
        }
        hasher.update(b"\0workgroup-count\0");
        match shape.workgroup_count {
            Some(count) => {
                hasher.update(&[1]);
                for axis in count {
                    hasher.update(&axis.to_le_bytes());
                }
            }
            None => {
                hasher.update(&[0]);
            }
        }
        hasher.update(b"\0output-bytes\0");
        hasher.update(&shape.output_bytes.to_le_bytes());
        let digest = hasher.finalize();
        let mut key = String::with_capacity(67);
        key.push_str("v1-");
        push_hex(digest.as_bytes(), &mut key);
        Self(key)
    }

    /// String form used in the TOML cache.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn push_hex(bytes: &[u8], out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
}

impl AsRef<str> for TunerProgramKey {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl TunerCache {
    /// Return the best workgroup size for the given key, if cached.
    #[must_use]
    pub fn get(&self, program_fp: &str) -> Option<[u32; 3]> {
        self.entries.get(program_fp).copied()
    }

    /// Return the cached decision for a typed tuner key.
    #[must_use]
    pub fn get_key(&self, key: &TunerProgramKey) -> Option<[u32; 3]> {
        self.get(key.as_str())
    }

    /// Record a decision.
    pub fn set(&mut self, program_fp: impl Into<String>, size: [u32; 3]) {
        self.entries.insert(program_fp.into(), size);
    }

    /// Record a decision under a typed key.
    ///
    /// HOT PATH (autotuner cache write): takes ownership of `key` so the fingerprint `String`
    /// moves into the map — `set(key.as_str(), …)` would allocate a second copy of the same bytes.
    pub fn set_key(&mut self, key: TunerProgramKey, size: [u32; 3]) {
        self.entries.insert(key.0, size);
    }

    /// Load from a TOML file. Missing file returns an empty cache.
    ///
    /// # Errors
    ///
    /// Returns when the file exists but contains invalid TOML.
    pub fn load(path: &Path) -> Result<Self, String> {
        let Ok(contents) = read_tuner_cache_bounded(path) else {
            return Ok(Self::default());
        };
        let parsed: toml::Value = toml::from_str(&contents).map_err(|error| {
            format!(
                "Fix: tuner cache `{}` is not valid TOML: {error}",
                path.display()
            )
        })?;
        let mut entries = BTreeMap::new();
        if let Some(table) = parsed.as_table() {
            for (key, value) in table {
                if let Some(array) = value.as_array() {
                    if array.len() == 3 {
                        let mut triple = [0u32; 3];
                        for (index, value) in array.iter().enumerate() {
                            if let Some(number) = value.as_integer() {
                                if let Ok(converted) = u32::try_from(number) {
                                    triple[index] = converted;
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
    /// Returns when the parent directory cannot be created or the file cannot
    /// be written.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "Fix: could not create tuner cache directory {}: {error}",
                    parent.display()
                )
            })?;
        }
        let mut out = String::with_capacity(tuner_cache_string_capacity(self.entries.len()));
        for (key, size) in &self.entries {
            let _ = writeln!(out, "\"{}\" = [{}, {}, {}]", key, size[0], size[1], size[2]);
        }
        fs::write(path, &out).map_err(|error| {
            format!(
                "Fix: could not write tuner cache {}: {error}",
                path.display()
            )
        })
    }
}

fn read_tuner_cache_bounded(path: &Path) -> std::io::Result<String> {
    use std::io::Read as _;

    let mut file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    if metadata.len() > MAX_TUNER_CACHE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("tuner cache exceeds {MAX_TUNER_CACHE_BYTES} byte limit"),
        ));
    }
    let mut text = String::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(MAX_TUNER_CACHE_BYTES + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_TUNER_CACHE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "tuner cache exceeded bounded read limit",
        ));
    }
    Ok(text)
}

/// Best-of-N measurement result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TuningMeasurement {
    /// Winning workgroup size.
    pub workgroup_size: [u32; 3],
    /// Measured elapsed nanoseconds for the winner.
    pub elapsed_ns: u64,
}

/// Workgroup-size autotuner.
pub struct Tuner {
    mode: Mode,
    cache: TunerCache,
    cache_path: PathBuf,
}

impl Tuner {
    /// Build a new tuner for the adapter fingerprinted as `adapter_fp`.
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

    /// Candidate workgroup sizes bounded by `max_invocations`.
    #[must_use]
    pub fn candidates_for(&self, max_invocations: u32) -> Vec<u32> {
        let mut candidates = Vec::new();
        candidates
            .try_reserve_exact(CANDIDATES.len())
            .unwrap_or_else(|error| {
                panic!(
                    "Vyre tuner could not reserve {} workgroup candidate slot(s): {error}. Fix: shrink the candidate table or split tuning into pages.",
                    CANDIDATES.len()
                )
            });
        candidates.extend(
            CANDIDATES
                .iter()
                .copied()
                .filter(|candidate| *candidate <= max_invocations),
        );
        candidates
    }

    /// Default workgroup size used without cache data.
    #[must_use]
    pub const fn default_workgroup_size() -> [u32; 3] {
        crate::pipeline::DEFAULT_1D_WORKGROUP_SIZE
    }

    /// Mode this tuner is running in.
    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.mode
    }

    /// Resolve the workgroup size for a program key.
    #[must_use]
    pub fn resolve(&self, program_fp: &str) -> [u32; 3] {
        self.cache
            .get(program_fp)
            .unwrap_or_else(Self::default_workgroup_size)
    }

    /// Resolve the workgroup size for a typed program/static-shape key.
    #[must_use]
    pub fn resolve_key(&self, key: &TunerProgramKey) -> [u32; 3] {
        self.resolve(key.as_str())
    }

    /// Record a sweep outcome in memory.
    pub fn record_decision(&mut self, program_fp: impl Into<String>, size: [u32; 3]) {
        self.cache.set(program_fp, size);
    }

    /// Record a sweep outcome for a typed key.
    pub fn record_key_decision(&mut self, key: TunerProgramKey, size: [u32; 3]) {
        self.cache.set_key(key, size);
    }

    /// Measure candidate sizes and choose the fastest one.
    ///
    /// # Errors
    ///
    /// Returns a backend timing error from [`BackendTimer`].
    pub fn best_of<T: BackendTimer>(
        &self,
        program: &Program,
        candidates: impl IntoIterator<Item = [u32; 3]>,
        timer: &mut T,
    ) -> Result<Option<TuningMeasurement>, T::Error> {
        let mut best = None;
        for workgroup_size in candidates {
            let elapsed_ns = timer.measure_candidate_ns(program, workgroup_size)?;
            let measurement = TuningMeasurement {
                workgroup_size,
                elapsed_ns,
            };
            if best
                .map(|current: TuningMeasurement| elapsed_ns < current.elapsed_ns)
                .unwrap_or(true)
            {
                best = Some(measurement);
            }
        }
        Ok(best)
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

/// Snapshot of live behavior the tuner consumes for adaptive resizing.
#[derive(Debug, Clone)]
pub struct TunerFeedback {
    /// `(opcode_id, execution_count)` pairs from backend metrics.
    pub per_opcode_counts: Vec<(u32, u32)>,
    /// Total wall-time in microseconds.
    pub wall_time_us: u64,
    /// Idle microseconds inside the window.
    pub idle_us: u64,
    /// Workgroup size x this feedback was gathered on.
    pub observed_workgroup_size_x: u32,
    /// Observed throughput per microsecond.
    pub observed_throughput_per_us: f64,
}

/// Hysteresis-based default resize policy.
#[derive(Debug, Clone)]
pub struct DefaultPolicy {
    /// Upper bound from the adapter capability probe.
    pub adapter_max_workgroup_size_x: u32,
    /// Floor below which we never shrink.
    pub minimum_workgroup_size_x: u32,
    /// Throughput below which we grow.
    pub saturation_threshold_per_us: f64,
    /// Idle time above which we shrink.
    pub idle_shrink_us: u64,
}

impl Default for DefaultPolicy {
    fn default() -> Self {
        Self {
            adapter_max_workgroup_size_x: 1024,
            minimum_workgroup_size_x: 32,
            saturation_threshold_per_us: 1.0,
            idle_shrink_us: 100_000,
        }
    }
}

impl DefaultPolicy {
    /// Suggest a new workgroup size for the next feedback window.
    #[must_use]
    pub fn suggest_resize(&self, feedback: &TunerFeedback) -> Option<u32> {
        let current = feedback.observed_workgroup_size_x.max(1);
        if feedback.idle_us > self.idle_shrink_us {
            let shrunk = current / 2;
            if shrunk >= self.minimum_workgroup_size_x && shrunk != current {
                return Some(shrunk);
            }
            return None;
        }
        if feedback.observed_throughput_per_us < self.saturation_threshold_per_us {
            let grown = current.checked_mul(2)?;
            if grown <= self.adapter_max_workgroup_size_x && grown != current {
                return Some(grown);
            }
        }
        None
    }
}

fn tuner_cache_string_capacity(entries: usize) -> usize {
    entries.checked_mul(96).unwrap_or_else(|| {
        panic!(
            "tuner cache entry count {entries} overflows serialized capacity estimate. Fix: shard the tuner cache before formatting."
        )
    })
}

fn dirs_cache_root() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
        PathBuf::from(xdg)
    } else if let Some(home) = std::env::var_os("HOME") {
        let mut path = PathBuf::from(home);
        path.push(".cache");
        path
    } else {
        PathBuf::from(".")
    }
}
