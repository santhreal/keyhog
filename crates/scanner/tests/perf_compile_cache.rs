// This whole tripwire measures the Hyperscan (`simd`) cold-compile path and
// calls `set_hyperscan_cache_dir`, which only exists under the `simd` feature.
// Gate the binary on `simd` so the default `simdsieve`-only test build (which
// has no Hyperscan) does not fail to compile against a feature-gated symbol.
#![cfg(feature = "simd")]
//! PERF TRIPWIRE, cold detector-compile is a SERIAL Hyperscan build that
//! does not use the machine's cores.
//!
//! ## What this pins
//!
//! Cold-starting the scanner compiles every detector pattern into a Hyperscan
//! `BlockDatabase` via a SINGLE serial call:
//!
//!   crates/scanner/src/simd.rs:283  `Builder::build::<BlockMode>(&patterns_obj)`
//!   crates/scanner/src/simd.rs:279  `let mut attempts = hs_pats.to_vec();`  (clones the whole pattern vec)
//!   driven from crates/scanner/src/engine/backend_prepared.rs:81
//!     `crate::simd::backend::HsScanner::compile(&pattern_refs)`
//!   and crates/scanner/src/compiled_scanner/compile.rs `build_simd_scanner(...)`.
//!
//! That one `Builder::build` compiles all 899 detector regexes on ONE core
//! while every other core idles. The Rust-side parallel phase
//! (`build_compile_state`, rayon `par_iter` over detectors) is already cheap
//! (~5 ms measured); ~99.7% of the cold compile is the serial Hyperscan C-side
//! NFA/DFA build.
//!
//! ## Measured (release-fast, 32-core 9950X, GPU policy off, HS disk cache cleared)
//!
//!   build_compile_state (rayon, parallel) .......   ~5 ms   (already fast)
//!   serial Builder::build over 899 patterns ..... ~1600 ms  (the defect)
//!   ----------------------------------------------------------------------
//!   cold compile, 899 detectors ................. ~1600-1650 ms  (best-of-3)
//!   cold compile, 449 detectors (first half) ....  ~840 ms       (best-of-3)
//!   full(899) / half(449) cold ratio ............  ~1.89-1.95x   <-- LINEAR
//!   warm compile (HS deserialized from disk) .....  ~21 ms       (best-of-5)
//!   cold / warm ratio ...........................  ~78x
//!
//! The full/half ratio of ~1.9 is the structural signature of a SERIAL
//! compile: doubling the pattern count doubles the wall-clock, because no
//! second core is doing any of the build. The docs cite the cold compile as
//! repeated compile cost; the disk cache already collapses
//! cross-process cold-start to ~21 ms, but a daemon/watch process that loads
//! a fresh (uncached) detector set per job still eats the full serial build.
//!
//! ## Target (what the optimized code must hit)
//!
//! Split the pattern set into K independent shards, compile K `BlockDatabase`s
//! on a rayon pool (each `Builder::build` is independent and CPU-bound), scan
//! all K at runtime, and union the matches. With K shards on a >=4-core box the
//! cold compile drops to ~`serial / min(K, cores)` (bounded by the largest
//! shard), so DOUBLING the pattern count is absorbed by parallelism instead of
//! doubling wall-clock. Concretely: full/half cold ratio must fall from ~1.9x
//! to <= 1.4x.
//!
//! ## Why a RATIO test (and not absolute ms)
//!
//! Both halves of the ratio are in-process cold compiles on the SAME machine,
//! so absolute CPU speed, Hyperscan version, and detector mix all cancel. The
//! number measured is the *scaling exponent* of the compile w.r.t. pattern
//! count, which is hardware-independent: ~linear (serial) today, ~flat
//! (parallel) once fixed. best-of-3 on each side strips scheduler noise. The
//! assertion is gated on >= 4 cores because a 1-2 core runner physically
//! cannot show a parallel speedup and would make the ratio test meaningless
//! there.
//!
//! ## Recall guard the fixer must keep green
//!
//! Sharding must NOT drop any pattern. `all_detectors_self_validate.rs`
//! (every detector fires on its canonical positive) is the guard: if a shard
//! is lost, detectors in it go silent and that test reddens. This test only
//! measures compile TIME; it must never become a license to compile fewer
//! patterns.
//!
//! Run: `cargo test -p keyhog-scanner --test perf_compile_cache --profile release-fast`
//! A FAIL here today is correct and expected; it clears once the cold compile
//! parallelizes across shards.

mod support;
use support::paths::detector_dir;

use keyhog_scanner::gpu::{gpu_runtime_policy, set_gpu_runtime_policy, GpuRuntimePolicy};
use keyhog_scanner::CompiledScanner;
use std::time::{Duration, Instant};

/// full/half cold-compile ratio must drop to at most this once the serial
/// `Builder::build` is sharded across cores. Measured today: ~1.89-1.95x
/// (linear -> serial). A parallel shard compile on a >=4-core box brings it
/// to ~1.0-1.2x; 1.4 sits between the broken (~1.9) and fixed (~1.1) regimes
/// with margin on both sides so neither noise nor a 4-core floor flips it.
const MAX_FULL_OVER_HALF_RATIO: f64 = 1.4;

/// Minimum cores for the parallel optimization to be physically possible.
/// Below this the ratio test is skipped (it cannot meaningfully pass even
/// with the fix), so it would be unfair to assert there.
const MIN_CORES_FOR_RATIO: usize = 4;

fn isolated_cache_dir(tag: &str) -> std::path::PathBuf {
    // The SIMD backend validates explicit cache dirs under $HOME; anchor the
    // isolated dir there so the cache-clear-per-iteration logic below is the
    // ONLY thing controlling cold vs warm.
    let home = std::env::var_os("HOME").expect("HOME must be set to run this perf test");
    let base = std::path::PathBuf::from(home)
        .join(".cache")
        .join("keyhog-perf");
    std::fs::create_dir_all(&base).expect("create perf cache base");
    let dir = base.join(format!("perf-compile-cache-{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create isolated cache dir");
    dir
}

fn best_of<F: FnMut() -> Duration>(k: usize, mut f: F) -> Duration {
    (0..k).map(|_| f()).min().expect("k >= 1")
}

struct GpuPolicyGuard(GpuRuntimePolicy);

impl GpuPolicyGuard {
    fn set(policy: GpuRuntimePolicy) -> Self {
        let prior = gpu_runtime_policy();
        set_gpu_runtime_policy(policy);
        Self(prior)
    }
}

impl Drop for GpuPolicyGuard {
    fn drop(&mut self) {
        set_gpu_runtime_policy(self.0);
    }
}

#[test]
fn cold_compile_must_parallelize_across_pattern_shards() {
    // Force the CPU/SIMD path: this tripwire is about the Hyperscan compile,
    // not GPU init. The explicit disabled policy keeps `compile()` from
    // touching CUDA/wgpu.
    let _gpu_policy = GpuPolicyGuard::set(GpuRuntimePolicy::Disabled);

    let dir = isolated_cache_dir("shard-ratio");
    keyhog_scanner::set_hyperscan_cache_dir(Some(dir.clone()));

    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let n = detectors.len();
    assert!(
        n >= 600,
        "expected the full ~899-detector corpus, got {n}; this tripwire \
         measures the serial Hyperscan compile of the real corpus"
    );
    let half: Vec<_> = detectors.iter().take(n / 2).cloned().collect();

    let clear = |d: &std::path::Path| {
        let _ = std::fs::remove_dir_all(d);
        std::fs::create_dir_all(d).expect("recreate cache dir");
    };

    // Each iteration clears the HS disk cache first, so EVERY compile pays the
    // full serial Hyperscan `Builder::build`. best-of-3 -> the min strips
    // scheduler/IO noise and leaves the pure compute cost.
    let cold_full = best_of(3, || {
        clear(&dir);
        let t = Instant::now();
        let s = CompiledScanner::compile(detectors.clone()).expect("cold full compile");
        let e = t.elapsed();
        std::hint::black_box(&s);
        e
    });

    let cold_half = best_of(3, || {
        clear(&dir);
        let t = Instant::now();
        let s = CompiledScanner::compile(half.clone()).expect("cold half compile");
        let e = t.elapsed();
        std::hint::black_box(&s);
        e
    });

    let ratio = cold_full.as_secs_f64() / cold_half.as_secs_f64();
    let cores = std::thread::available_parallelism()
        .map(|c| c.get())
        .unwrap_or(1);

    eprintln!(
        "perf_compile_cache: cores={cores} cold_full({n})={:.1}ms cold_half({})={:.1}ms \
         full/half={ratio:.2}x (target <= {MAX_FULL_OVER_HALF_RATIO:.2}x)",
        cold_full.as_secs_f64() * 1000.0,
        half.len(),
        cold_half.as_secs_f64() * 1000.0,
    );

    if cores < MIN_CORES_FOR_RATIO {
        eprintln!(
            "perf_compile_cache: SKIP ratio assertion - {cores} cores (< {MIN_CORES_FOR_RATIO}); \
             parallel shard compile cannot show a speedup on this machine."
        );
        keyhog_scanner::set_hyperscan_cache_dir(None);
        return;
    }

    keyhog_scanner::set_hyperscan_cache_dir(None);

    assert!(
        ratio <= MAX_FULL_OVER_HALF_RATIO,
        "SERIAL Hyperscan compile: doubling the pattern set ({} -> {} detectors) \
         multiplied cold-compile wall-clock by {ratio:.2}x (target <= {MAX_FULL_OVER_HALF_RATIO:.2}x) \
         on a {cores}-core machine. ~99.7% of the cold compile is a single serial \
         `Builder::build::<BlockMode>` call at crates/scanner/src/simd.rs:283 \
         (driven from engine/backend_prepared.rs:81); the rayon-parallel \
         build_compile_state phase is already ~5ms. The full corpus compiled in \
         {:.0}ms while the half compiled in {:.0}ms - linear scaling means every \
         core but one sat idle during the build. \
         FIX: split the pattern set into K shards, compile K BlockDatabases on a \
         rayon pool, scan all K and union the matches; doubling patterns is then \
         absorbed by parallelism (ratio -> ~1.0-1.2x). MUST keep \
         all_detectors_self_validate green so no shard is dropped.",
        half.len(),
        n,
        cold_full.as_secs_f64() * 1000.0,
        cold_half.as_secs_f64() * 1000.0,
    );
}
