#![forbid(unsafe_code)]
#![warn(missing_docs)]
// Every lint below is allowed for a documented reason. New lints from
// nursery/pedantic/restriction are NOT auto-allowed  -  broad blanket allows
// were removed deliberately so that future clippy findings surface as CI
// warnings instead of being silently swallowed.
#![allow(
    // Auto-generated op wrappers replay derive attributes by design.
    clippy::duplicated_attributes,
    // GPU buffer layout types (bind-group slot tuples) are inherently complex.
    clippy::type_complexity,
    // Shader-side math and wire-format POD structs do intentional integer
    // casts; the conform gate verifies byte-identity with the CPU reference.
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    // Explicit clones on Copy improve readability in serial layers where
    // semantic ownership matters more than cycle count.
    clippy::clone_on_copy,
    // Three-branch comparisons are natural in range-check oracles.
    clippy::comparison_chain,
    // Vyre uses explicit invariant violations (expect/unwrap) with `Fix:`
    // prose  -  not graceful degradation  -  per the engineering standard.
    clippy::expect_used,
    // Generic collections take external hashers by design.
    clippy::implicit_hasher,
    // SHA/hash compressors use the canonical single-letter state vars
    // (a,b,c,d,e,f,g,h per FIPS 180-4).
    clippy::many_single_char_names,
    // Error prose is centralized in the `Error` enum; per-fn `# Errors`
    // sections duplicate that contract.
    clippy::missing_errors_doc,
    // Panics document invariant violations with `Fix:` prose inline.
    clippy::missing_panics_doc,
    // Template-generated ops don't always merit `#[must_use]`.
    clippy::must_use_candidate,
    // Builder APIs take owned values by design.
    clippy::needless_pass_by_value,
    // Indexed arithmetic is clearer than iterator chains for GPU-shape loops.
    clippy::needless_range_loop,
    // Generated target-text strings use `r##` for quote safety.
    clippy::needless_raw_string_hashes,
    // Type names repeat module names for cross-crate discoverability.
    clippy::module_name_repetitions,
    // `mod X` in `X.rs` is the canonical vyre module layout.
    clippy::module_inception,
    // Math code uses short similar names (a/A, x/X) by convention.
    clippy::similar_names,
    // Internal helpers with stdlib-adjacent names are intentional for clarity.
    clippy::should_implement_trait,
    // Enforcer dispatch arms can share a body but represent distinct cases.
    clippy::match_same_arms,
    // Hot paths in the pipeline assemble strings incrementally.
    clippy::format_push_string,
    // GPU kernel dispatchers take many parameters by design (buffer slots).
    clippy::too_many_arguments,
    // Hash compressors and regex compilers have long inlined bodies.
    clippy::too_many_lines,
    // Trait signatures force `&T` for small Copy types.
    clippy::trivially_copy_pass_by_ref,
    // `Result<T, E>` with a single error variant keeps the API
    // forward-compatible as new error variants land.
    clippy::unnecessary_wraps,
    // Or-patterns are expanded for readability in large match tables.
    clippy::unnested_or_patterns,
    // GPU buffer sizes like `0x12345678` are more readable without `_`
    // separators in shader contexts.
    clippy::unreadable_literal,
    // Prose doc comments use type names that clippy wants backticked; our
    // doc style sentences already read naturally.
    clippy::doc_markdown
)]
#![cfg_attr(not(test), deny(clippy::todo, clippy::unimplemented))]
//! # vyre  -  LLVM-for-GPU
//!
//! Vyre is a GPU compute substrate centered on the `Program` type. Just as
//! LLVM lets frontends emit a single IR that lowers to many processor targets,
//! vyre lets frontends emit a single `Program` that lowers through any
//! registered backend or the pure-Rust reference interpreter. The crate root
//! re-exports the frozen public API: the `Program` type, the `VyreBackend`
//! trait, and the standard operation library.
//!
//! Frontends, backends, and conformance tools depend only on the stable
//! types exported here. Changing the target-text lowering path never breaks a
//! frontend; changing a frontend AST never affects backend dispatch logic.
//! This module is the single source of truth for the vyre public API.

/// The vyre Program model.
///
/// This module defines `Program`, the frozen, serializable model that every
/// frontend emits and every backend consumes. It has zero external
/// dependencies so that spec tools can parse it without pulling in GPU
/// libraries.
/// Public API re-export.
pub use vyre_foundation::ir;

/// Soundness lattice for dataflow primitives. Canonical home is
/// `vyre-foundation`; re-exported here so vyre-libs (and any downstream
/// consumer) reaches it via `vyre::soundness`. Per the LEGO discipline,
/// vyre never imports from domain dataflow crates  -  this is the originating definition.
pub use vyre_foundation::soundness;

// Layer 1 and Layer 2 operation specifications live in vyre-libs.
// The crate root remains the single stable import surface for consumers.

/// Program lowering to the substrate-neutral kernel descriptor.
///
/// Lowering transforms a validated `Program` into
/// [`lower::KernelDescriptor`]. Emit crates then turn that descriptor into
/// target artifacts. Frontends do not depend on this module; it is consumed
/// by backend and emitter implementations.
/// Public API re-export.
pub mod lower {
    /// Canonical Program -> KernelDescriptor lowering entry point.
    pub use vyre_lower::lower::lower;
    pub use vyre_lower::*;
}

/// IR-to-IR optimizer pass framework.
///
/// `optimizer` provides the registered pass scheduler and reference
/// optimization passes used by frontends that want fixpoint IR cleanup before
/// lowering.
/// Public API re-export.
pub use vyre_foundation::optimizer;

/// Wire-format CPU-reference byte ABI contract.
/// Public API re-export.
#[cfg(any(test, feature = "cpu-parity"))]
pub use vyre_foundation::cpu_op;
/// CPU reference implementations shared across backends.
/// Public API re-export.
#[cfg(any(test, feature = "cpu-parity"))]
pub use vyre_foundation::cpu_references;
/// Substrate-neutral memory ordering model.
/// Public API re-export.
pub use vyre_foundation::memory_model;
/// Substrate-neutral memory ordering type.
/// Public API re-export.
pub use vyre_foundation::MemoryOrdering;

/// Distribution-aware runtime algorithm selection.
/// Public API re-export.
pub use vyre_driver::routing;

/// Substrate-neutral execution planning for performance and accuracy tracks.
/// Public API re-export.
pub use vyre_foundation::execution_plan;

/// Unified error types for the entire crate.
/// Public API re-export.
pub use vyre_driver::error;

/// Structured, machine-readable diagnostics.
/// Public API re-export.
pub use vyre_driver::diagnostics;

/// Backend trait surface  -  `VyreBackend`, `Executable`,
/// `Streamable`, `DispatchConfig`, `BackendError`,
/// `ErrorCode`. The whole backend contract every driver crate
/// implements against.
/// Public API re-export.
/// Public API re-export.
pub use vyre_driver::backend;
/// Re-export of the native scan match result type from the foundation crate.
/// Public API re-export.
/// Public API re-export.
pub use vyre_foundation::match_result;

/// Pipeline-mode dispatch: compile a Program once, dispatch repeatedly.
/// Public API re-export.
/// Public API re-export.
pub use vyre_driver::pipeline;

// Previously: pub mod bytecode  -  a 637-LOC stack-machine VM publicly
// re-exported from core. Deleted 2026-04-17. The NFA scan micro-interpreter
// that carried the remaining bytecode was deleted 2026-04-19. Rule evaluators
// compose ops in vyre IR directly. No interpreter surface remains in core.

pub use vyre_driver::{
    BackendError, BackendRegistration, CompiledPipeline, DispatchConfig, Error, Executable, Memory,
    MemoryRef, OutputBuffers, ResidentGraphReuseTelemetry, ResidentGraphReuseTelemetryError,
    TypedDispatchExt, VyreBackend,
};

/// Persistent-thread dispatch policy for dispatch paths.
pub use vyre_driver::persistent::PersistentThreadMode;
/// Speculation policy for dispatch paths.
pub use vyre_driver::speculate::SpeculationMode;

/// Re-export of the core IR program type and validation entry point.
///
/// `Program` is the frozen IR container. `validate` is the function that
/// checks a program for structural and semantic correctness before it is
/// handed to a backend.
pub use ir::{validate, InterpCtx, NodeId, NodeStorage, OpId, Program, Value};

/// Re-export of the native scan match result type.
///
/// `Match` represents a byte-range hit produced by pattern-scanning engines.
pub use vyre_foundation::match_result::Match;

/// Domain-neutral byte-range type.
pub use vyre_foundation::ByteRange;

/// R2: single canonical pre-lowering optimize entry point.
///
/// Bundles the canonical pre-lowering pipeline so every consumer wires one
/// function instead of three. Today consumers separately call
/// `pre_lowering::optimize`, then `vyre_lower::lower`, then a
/// backend-specific emit. This wrapper keeps the optimization stage  -
/// the part that's stable across backends  -  behind one symbol so
/// adding a new substrate row does not require N consumer changes.
///
/// The lowering and emit stages remain backend-specific and are
/// invoked separately by the chosen `VyreBackend`. This function
/// returns the optimized `Program` ready to hand to any backend's
/// `dispatch` / `compile` path.
///
/// **N9 substrate composition fingerprint cache.** Repeated identical
/// inputs (same `program.fingerprint()`) skip the substrate stack
/// entirely. The cache is process-local, bounded to
/// [`OPTIMIZE_CACHE_CAPACITY`] entries, and uses O(1) fingerprint lookup
/// with FIFO eviction  -  long-running daemons get the cache without
/// unbounded memory.
/// On a cache hit, `optimize` clones the cached `Program` instead of
/// re-running the (canonicalize + region_inline + scheduler fixpoint
/// + CSE + DCE + phase-4) pipeline. The substrate stack is purely
/// functional in `Program`, so caching by structural fingerprint is
/// safe  -  same input bytes, same output bytes.
///
/// # Example
///
/// ```no_run
/// use vyre::{optimize, Program};
/// fn run(program: Program) -> Program {
///     optimize(program)
/// }
/// ```
#[must_use]
pub fn optimize(program: Program) -> Result<Program, vyre_foundation::optimizer::OptimizerError> {
    let key = program.fingerprint();
    if let Some(cached) = optimize_cache::get(&key) {
        return Ok(cached);
    }
    let optimized = vyre_foundation::optimizer::pre_lowering::optimize(program);
    optimize_cache::put(key, &optimized);
    Ok(optimized)
}

/// Device-aware public optimizer entry point.
///
/// Runs adapter-shaped workgroup autotuning from a neutral
/// [`DeviceProfile`] before the canonical pre-lowering optimization
/// pipeline. Consumers with a live backend should prefer
/// [`optimize_for_backend`]; consumers with a saved device signature
/// can call this directly.
#[must_use]
pub fn optimize_for_device(
    program: Program,
    profile: &vyre_driver::DeviceProfile,
) -> Result<Program, vyre_foundation::optimizer::OptimizerError> {
    let key = device_optimize_key(&program, profile);
    if let Some(cached) = optimize_cache::get_device(&key) {
        return Ok(cached);
    }
    let tuned = vyre_foundation::optimizer::passes::autotune::Autotune::transform_for_adapter(
        program,
        &profile.adapter_caps(),
    )
    .program;
    let optimized = optimize(tuned)?;
    optimize_cache::put_device(key, &optimized);
    Ok(optimized)
}

/// Device-aware public optimizer entry point for a live backend.
#[must_use]
pub fn optimize_for_backend(
    program: Program,
    backend: &dyn vyre_driver::VyreBackend,
) -> Result<Program, vyre_foundation::optimizer::OptimizerError> {
    let profile = backend.device_profile();
    optimize_for_device(program, &profile)
}

fn device_optimize_key(program: &Program, profile: &vyre_driver::DeviceProfile) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"vyre-core-optimize-device-v1\0");
    hasher.update(&program.fingerprint());
    hasher.update(profile.backend.as_bytes());
    hasher.update(&[u8::from(profile.supports_subgroup_ops)]);
    hasher.update(&[u8::from(profile.supports_indirect_dispatch)]);
    hasher.update(&[u8::from(profile.supports_f16)]);
    hasher.update(&[u8::from(profile.supports_bf16)]);
    hasher.update(&[u8::from(profile.supports_tensor_cores)]);
    hasher.update(&profile.max_workgroup_size[0].to_le_bytes());
    hasher.update(&profile.max_workgroup_size[1].to_le_bytes());
    hasher.update(&profile.max_workgroup_size[2].to_le_bytes());
    hasher.update(&profile.max_invocations_per_workgroup.to_le_bytes());
    hasher.update(&profile.max_shared_memory_bytes.to_le_bytes());
    hasher.update(&profile.subgroup_size.to_le_bytes());
    hasher.update(&profile.compute_units.to_le_bytes());
    hasher.update(&profile.ideal_unroll_depth.to_le_bytes());
    hasher.update(&profile.ideal_vector_pack_bits.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// N9 cache capacity (entries). Sized to hold the working set of a
/// long-running scanner without unbounded growth  -  each entry is
/// roughly the size of one optimized `Program`. 256 entries is
/// `~10MB` worst-case for typical scanner-shaped Programs.
pub const OPTIMIZE_CACHE_CAPACITY: usize = 256;

/// Process-local fingerprint -> Program cache for [`optimize`].
mod optimize_cache {
    use super::Program;
    use super::OPTIMIZE_CACHE_CAPACITY;
    use std::collections::{HashMap, VecDeque};
    use std::sync::Mutex;

    struct ProgramCacheShard {
        entries: HashMap<[u8; 32], Program>,
        fifo: VecDeque<[u8; 32]>,
    }

    impl ProgramCacheShard {
        fn new() -> Self {
            Self {
                entries: HashMap::with_capacity(OPTIMIZE_CACHE_CAPACITY),
                fifo: VecDeque::with_capacity(OPTIMIZE_CACHE_CAPACITY),
            }
        }

        fn get(&self, key: &[u8; 32]) -> Option<Program> {
            self.entries.get(key).cloned()
        }

        fn put(&mut self, key: [u8; 32], program: &Program) {
            if self.entries.contains_key(&key) {
                return;
            }
            if self.entries.len() >= OPTIMIZE_CACHE_CAPACITY {
                if let Some(evicted) = self.fifo.pop_front() {
                    self.entries.remove(&evicted);
                }
            }
            self.fifo.push_back(key);
            self.entries.insert(key, program.clone());
        }

        #[cfg(test)]
        fn clear(&mut self) {
            self.entries.clear();
            self.fifo.clear();
        }

        #[cfg(test)]
        fn len(&self) -> usize {
            self.entries.len()
        }
    }

    struct Cache {
        host: ProgramCacheShard,
        device: ProgramCacheShard,
    }

    impl Cache {
        fn new() -> Self {
            Self {
                host: ProgramCacheShard::new(),
                device: ProgramCacheShard::new(),
            }
        }
    }

    fn cache() -> &'static Mutex<Cache> {
        use std::sync::OnceLock;
        static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
        CACHE.get_or_init(|| Mutex::new(Cache::new()))
    }

    pub(super) fn get(key: &[u8; 32]) -> Option<Program> {
        let cache = cache().lock().ok()?;
        cache.host.get(key)
    }

    pub(super) fn put(key: [u8; 32], program: &Program) {
        let Ok(mut cache) = cache().lock() else {
            return;
        };
        cache.host.put(key, program);
    }

    pub(super) fn get_device(key: &[u8; 32]) -> Option<Program> {
        let cache = cache().lock().ok()?;
        cache.device.get(key)
    }

    pub(super) fn put_device(key: [u8; 32], program: &Program) {
        let Ok(mut cache) = cache().lock() else {
            return;
        };
        cache.device.put(key, program);
    }

    #[cfg(test)]
    pub(super) fn clear() {
        if let Ok(mut cache) = cache().lock() {
            cache.host.clear();
            cache.device.clear();
        }
    }

    #[cfg(test)]
    pub(super) fn len() -> usize {
        cache().lock().map(|c| c.host.len()).unwrap_or(0)
    }

    #[cfg(test)]
    pub(super) fn len_device() -> usize {
        cache().lock().map(|c| c.device.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod optimize_tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};
    use vyre_foundation::ir::{BufferDecl, DataType, Expr, Node};

    /// Serialise tests in this module so they don't race on the
    /// process-global cache. Each test takes the guard at entry and
    /// drops it at exit; the eviction test takes ~256 inserts which
    /// otherwise pollutes the count the other tests assert on.
    fn serial() -> MutexGuard<'static, ()> {
        static M: OnceLock<Mutex<()>> = OnceLock::new();
        M.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn sample_program() -> Program {
        Program::wrapped(
            vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
            [1, 1, 1],
            vec![Node::store("out", Expr::u32(0), Expr::u32(42))],
        )
    }

    #[test]
    fn optimize_is_cached_by_fingerprint() {
        let _g = serial();
        optimize_cache::clear();
        let p1 = sample_program();
        let p2 = sample_program();
        let first = optimize(p1).expect("Fix: optimize must succeed on sample_program");
        assert!(
            !first.entry().is_empty(),
            "optimized program must retain work"
        );
        let before = optimize_cache::len();
        let second = optimize(p2).expect("Fix: optimize must succeed on cache-hit path");
        assert!(
            !second.entry().is_empty(),
            "cached optimized program must retain work"
        );
        let after = optimize_cache::len();
        assert_eq!(
            before, after,
            "second optimize on identical fingerprint must hit the cache"
        );
        assert_eq!(before, 1, "cache must contain exactly one entry");
    }

    #[test]
    fn optimize_returns_equivalent_program_on_cache_hit() {
        let _g = serial();
        optimize_cache::clear();
        let p = sample_program();
        let first = optimize(p.clone()).expect("Fix: optimize must succeed on sample_program");
        let second = optimize(p).expect("Fix: optimize must succeed on cache-hit path");
        assert_eq!(
            first.fingerprint(),
            second.fingerprint(),
            "cache hit must return a Program with identical fingerprint"
        );
    }

    #[test]
    fn optimize_cache_evicts_at_capacity() {
        let _g = serial();
        optimize_cache::clear();
        // Build OPTIMIZE_CACHE_CAPACITY + 1 distinct programs by
        // varying the stored literal  -  each gets a unique fingerprint.
        for i in 0..(OPTIMIZE_CACHE_CAPACITY + 1) {
            let prog = Program::wrapped(
                vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
                [1, 1, 1],
                vec![Node::store("out", Expr::u32(0), Expr::u32(i as u32))],
            );
            let optimized =
                optimize(prog).expect("Fix: optimize must succeed on cache-eviction probe");
            assert!(
                !optimized.entry().is_empty(),
                "optimized cache-entry program must retain work"
            );
        }
        assert_eq!(
            optimize_cache::len(),
            OPTIMIZE_CACHE_CAPACITY,
            "cache must cap at OPTIMIZE_CACHE_CAPACITY entries"
        );
    }

    #[test]
    fn optimize_for_device_uses_device_specific_cache() {
        let _g = serial();
        optimize_cache::clear();
        let mut profile = vyre_driver::DeviceProfile::conservative("test");
        profile.max_workgroup_size = [256, 1, 1];
        profile.max_invocations_per_workgroup = 256;
        let p1 = sample_program();
        let p2 = sample_program();
        let first =
            optimize_for_device(p1, &profile).expect("Fix: optimize_for_device must succeed");
        let second = optimize_for_device(p2, &profile)
            .expect("Fix: optimize_for_device must succeed on cache hit");
        assert_eq!(first.fingerprint(), second.fingerprint());
        assert_eq!(
            optimize_cache::len_device(),
            1,
            "same program+device profile must hit the device optimize cache"
        );
        assert_eq!(
            optimize_cache::len(),
            1,
            "device optimization should still reuse the canonical optimize cache after tuning"
        );
    }
}

#[cfg(test)]

mod optimize_cache_structure_tests {
    #[test]
    fn host_and_device_optimize_caches_share_one_bounded_shard_type() {
        let source = include_str!("lib.rs");
        let release_path = source
            .split("\n#[cfg(test)]\nmod optimize_tests")
            .next()
            .expect("Fix: optimize cache release source must be visible");

        assert!(
            release_path.contains("struct ProgramCacheShard"),
            "Fix: optimize cache must centralize bounded cache behavior in one shard type."
        );
        assert!(
            !release_path.contains("device_entries") && !release_path.contains("device_fifo"),
            "Fix: host/device optimize caches must not duplicate eviction fields."
        );
    }
}

