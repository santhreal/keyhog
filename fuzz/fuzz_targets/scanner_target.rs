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

        // Fuzz the scan pipeline, not the full detector corpus. Compiling every
        // detector under libFuzzer's ASan instrumentation is the dominant cost
        // of this target's one-time init. That init executes inside fuzz unit
        // #0, so a full corpus can exhaust constrained hosted runners before a
        // real input is fuzzed. A representative, stride-sampled subset keeps
        // init bounded and deterministic while still driving decode-through,
        // suppression, scoring, and reporting. Full-corpus compile and
        // cross-backend scan parity are covered by the non-fuzz
        // `worst_case_backend_parity` test.
        const FUZZ_DETECTOR_CAP: usize = 64;
        let stride = (all.len() / FUZZ_DETECTOR_CAP).max(1);
        // The plan builder rejects any relation whose target is outside the
        // compiled set, and a stride sample can split a relation pair (e.g.
        // notion-integration-token -> notion-api-key), so the raw sample does
        // not always compile. Close the selection transitively over relation
        // targets: init stays bounded by the same order of magnitude while the
        // subset remains compilable.
        let mut chosen = vec![false; all.len()];
        for i in (0..all.len()).step_by(stride).take(FUZZ_DETECTOR_CAP) {
            chosen[i] = true;
        }
        {
            let index: std::collections::HashMap<&str, usize> = all
                .iter()
                .enumerate()
                .map(|(i, d)| (d.id.as_str(), i))
                .collect();
            let mut queue: Vec<usize> =
                (0..all.len()).filter(|&i| chosen[i]).collect();
            while let Some(i) = queue.pop() {
                for target in &all[i].detector_relations {
                    if let Some(&j) = index.get(target.detector_id.as_str()) {
                        if !chosen[j] {
                            chosen[j] = true;
                            queue.push(j);
                        }
                    }
                }
            }
        }
        let detectors: Vec<_> = all
            .into_iter()
            .zip(chosen)
            .filter_map(|(d, keep)| keep.then_some(d))
            .collect();

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
