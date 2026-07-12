//! Full-pipeline scanner fuzz target.
//!
//! Feeds arbitrary byte input to `CompiledScanner::scan` via a
//! synthetic `Chunk`. The fuzzer goal is to find:
//!
//!   - panics (unwrap on malformed input, slice OOB, integer
//!     overflow in unchecked arithmetic)
//!   - hangs (regex catastrophic backtracking, infinite loop in
//!     suppression heuristics)
//!   - memory blowups (allocator explosion on a 1 KiB input)
//!
//! Skips the detector-load cost by compiling once via `OnceLock`.
//! libfuzzer reuses the same process across iterations, so this is
//! the right shape: pay the ~500 ms detector compile once, then
//! fuzz `scan()` at full speed.

#![no_main]

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use libfuzzer_sys::fuzz_target;
use std::path::PathBuf;
use std::sync::OnceLock;

static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();

fn scanner() -> &'static CompiledScanner {
    SCANNER.get_or_init(|| {
        // Disable LeakSanitizer for this process. wgpu / NVIDIA's
        // libnvidia-glcore + libdbus allocate long-lived contexts at
        // GPU init that legitimately are not freed before process
        // exit (the driver outlives the user's process model). ASan
        // flags these as leaks and turns every fuzz run into a
        // false-positive crash. Disabling LSAN keeps real bugs
        // (use-after-free, double-free, OOB) detected while
        // ignoring exit-time GPU-context "leaks". SAFETY: only one
        // thread can be inside the OnceLock initializer at a time,
        // and no other thread has been spawned yet at this point.
        unsafe {
            std::env::set_var("LSAN_OPTIONS", "detect_leaks=0");
        }
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.pop(); // .../keyhog/fuzz -> .../keyhog
        d.push("detectors");
        let all = keyhog_core::load_detectors(&d).expect("detectors");

        // Fuzz the scan PIPELINE, not the full detector corpus. Compiling
        // every detector's Hyperscan database is the dominant cost of this
        // target's one-time init, and under libFuzzer's ASan instrumentation it
        // runs ~15s / ~1.6GB locally — but that init executes INSIDE fuzz unit
        // #0 (the empty input), so on core/memory-constrained hosted CI runners
        // it ballooned ~80x and blew past libFuzzer's 1200s per-unit timeout,
        // failing the smoke before a single real input was fuzzed. A
        // representative, stride-sampled subset keeps init sub-second and
        // deterministic on any runner while still driving the whole pipeline
        // (decode-through, suppression, scoring, reporting). Full-corpus
        // compile + cross-backend scan parity is covered by the non-fuzz
        // `worst_case_backend_parity` test, which is not under a per-unit
        // timeout — this smoke is for panics/hangs/OOM in `scan()`, not corpus
        // breadth.
        const FUZZ_DETECTOR_CAP: usize = 64;
        let stride = (all.len() / FUZZ_DETECTOR_CAP).max(1);
        let detectors: Vec<_> = all.into_iter().step_by(stride).take(FUZZ_DETECTOR_CAP).collect();

        CompiledScanner::compile(detectors).expect("scanner compile")
    })
}

fuzz_target!(|data: &[u8]| {
    // Restrict to valid UTF-8: converting random bytes via
    // `from_utf8_lossy` would just discard most fuzz cases. Direct
    // UTF-8 input lets the fuzzer drive the interesting code paths.
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // Bound input length: a 10 MiB random input is not a useful
    // fuzz case (it just stresses the regex engine's memory).
    if text.len() > 1024 * 64 {
        return;
    }
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "fuzz".into(),
            path: Some("fuzz_input.txt".into()),
            ..Default::default()
        },
    };
    let _ = scanner().scan(&chunk);
});
