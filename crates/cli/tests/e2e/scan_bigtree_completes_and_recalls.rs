//! T-perf-bigtree: PERF-01 deadlock regression guard (LIVENESS, not speed).
//!
//! WHY THIS FILE EXISTS
//! --------------------
//! PERF-01 was a SHIP-BLOCKER: `keyhog scan` of a large tree (the 2 GB / 94k-file
//! Linux kernel) HUNG FOREVER. Root cause: `FilesystemSource::chunks()` ran its
//! file-reader on the GLOBAL rayon pool; each reader task BLOCKED on the bounded
//! `sync_channel` `send` under backpressure, while the scanner's `par_iter`
//! needed a worker from that SAME global pool to drain the channel, a
//! reader-blocks-on-send ↔ scanner-needs-worker cycle. Small trees drained
//! before the channel ever saturated, so the SecretBench mirror (15k tiny files)
//! NEVER exposed it; the whole class was invisible because no large-tree scan
//! test existed. The fix runs the reader on a DEDICATED rayon pool so the
//! scanner's global pool always has a worker.
//!
//! WHAT THIS GUARDS
//! ----------------
//! This is a LIVENESS contract, not a wall-clock target: a healthy build
//! finishes the generated tree in a few seconds; a DEADLOCKED build never
//! finishes. So a single GENEROUS watchdog deadline cleanly separates the two
//! without flaking on slow CI cores (unlike a tight ms bound). The tree is sized
//! to keep the bounded producer→scanner channel SATURATED for the bulk of the
//! run, the only state in which the PERF-01 cycle can form, so re-folding the
//! reader back onto the global pool would hang here.
//!
//! The recall assertion (every planted secret surfaces) proves the scan actually
//! processed the whole tree rather than exiting early / dropping files: a "fast"
//! scan that silently skipped the backpressured tail would pass a bare
//! completion check but FAIL the recall set here.
//!
//! TUNING (Tier-A: env overrides compiled defaults)
//! ------------------------------------------------
//!   KEYHOG_BIGTREE_FILES        total files to generate (default 12_000)
//!   KEYHOG_BIGTREE_TIMEOUT_SECS watchdog deadline    (default 300)
//! The default catches gross regressions on any multicore CI box; nightly /
//! strict runners crank `KEYHOG_BIGTREE_FILES` to ~94_000 for the full-scale
//! stress. The backend is pinned to SIMD (`--no-gpu`) for determinism 
//! PERF-01 reproduced under BOTH backends, so the channel-topology guard is
//! backend-independent and SIMD keeps the test runnable on GPU-less CI.

use crate::e2e::support::binary;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// Plant the canonical, known-detected AWS access key id in every `STRIDE`-th
/// file. Split across `concat!` so this test's OWN source does not carry a
/// literal `AKIA…` shape (keyhog dogfood-scans its own tree).
const AWS_KEY: &str = concat!("AK", "IAQYLPMN5HFIQR7XYA");
/// One planted file per this many files → ~200 planted at the 12k default.
const STRIDE: usize = 60;
/// Flat-ish fan-out so no single directory holds the whole tree.
const FILES_PER_DIR: usize = 250;

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default)
}

/// Generate the wide tree. Returns (tempdir, set of UNIQUE planted basenames).
/// Basenames (not full paths) make the recall check robust to absolute-vs-
/// relative / separator differences in the reporter's `file_path`.
fn build_wide_tree(total: usize) -> (TempDir, std::collections::BTreeSet<String>) {
    let dir = TempDir::new().expect("tempdir");
    let root = dir.path();
    let mut planted = std::collections::BTreeSet::new();

    for i in 0..total {
        let sub = root.join(format!("d{:05}", i / FILES_PER_DIR));
        if i % FILES_PER_DIR == 0 {
            std::fs::create_dir_all(&sub).expect("mkdir");
        }
        if i % STRIDE == 0 {
            // Planted file: highest-confidence `.env`-style assignment context.
            let name = format!("planted_{i:07}.env");
            let path = sub.join(&name);
            let mut f = std::fs::File::create(&path).expect("create planted");
            // One canonical key per planted file; `--dedup none` keeps each
            // occurrence as its own finding keyed on its own file_path.
            writeln!(f, "AWS_ACCESS_KEY_ID = \"{AWS_KEY}\"").expect("write planted");
            planted.insert(name);
        } else {
            // Benign, low-entropy noise: no assignment-to-token, no long alnum
            // runs, no secret-shaped literals, pure tree bulk to create the
            // sustained channel backpressure PERF-01 needed.
            let path = sub.join(format!("noise_{i:07}.go"));
            let mut f = std::fs::File::create(&path).expect("create noise");
            let mut s = String::with_capacity(160);
            s.push_str("// the quick brown fox jumps over the lazy dog\n");
            s.push_str("package widget\n");
            for j in 0..3 {
                s.push_str("func step() { advance the cursor by one }\n");
                let _ = j;
            }
            f.write_all(s.as_bytes()).expect("write noise");
        }
    }
    (dir, planted)
}

/// Run `keyhog scan` on `root`, writing JSON to `out`, under a watchdog. Panics
/// (with a PERF-01 message) if the scan does not finish before `deadline`.
fn scan_with_watchdog(root: &Path, out: &Path, deadline: Duration) -> i32 {
    let mut child = Command::new(binary())
        .args([
            "scan",
            "--backend",
            "simd",
            "--no-gpu",
            "--daemon=off",
            "--dedup",
            "none",
            "--format",
            "json",
            "--output",
        ])
        .arg(out)
        .arg(root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn keyhog scan");

    let start = Instant::now();
    loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => {
                return status.code().unwrap_or(-1);
            }
            None => {
                if start.elapsed() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!(
                        "PERF-01 REGRESSION: `keyhog scan` of a {}-file tree did not complete \
                         within {}s, the source reader pool is starving the scanner's global \
                         rayon pool again (reader-blocks-on-send ↔ scanner-needs-worker cycle). \
                         Re-check that FilesystemSource::chunks() runs the reader on a DEDICATED \
                         pool (crates/sources/src/filesystem.rs).",
                        std::env::var("KEYHOG_BIGTREE_FILES").unwrap_or_else(|_| "default".into()),
                        deadline.as_secs(),
                    );
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

#[test]
fn bigtree_scan_completes_under_deadline_with_full_recall() {
    let total = env_usize("KEYHOG_BIGTREE_FILES", 12_000);
    let deadline = Duration::from_secs(env_usize("KEYHOG_BIGTREE_TIMEOUT_SECS", 300) as u64);

    let (dir, planted) = build_wide_tree(total);
    assert!(
        !planted.is_empty(),
        "test setup: STRIDE={STRIDE} produced no planted files for {total} total"
    );

    let out = dir.path().join("findings.json");
    let code = scan_with_watchdog(dir.path(), &out, deadline);

    // Completed (watchdog did not fire) AND found secrets → exit 1.
    assert_eq!(
        code, 1,
        "scan completed but exit code was {code} (expected 1: planted secrets present)"
    );

    let written = std::fs::read_to_string(&out).expect("findings output file");
    let arr = serde_json::from_str::<serde_json::Value>(&written)
        .expect("findings json")
        .as_array()
        .expect("findings array")
        .clone();

    // RECALL: every planted file must surface its key. Collect the distinct
    // file basenames that appear in ANY finding (detector-agnostic: robust to
    // which detector wins per file under cross-detector dedup) and intersect
    // with the planted set. A backpressure-tail drop would shrink this set.
    let found_paths: std::collections::BTreeSet<String> = arr
        .iter()
        .filter_map(|f| f.get("location").and_then(|l| l.get("file_path")))
        .filter_map(|p| p.as_str())
        .filter_map(|p| {
            Path::new(p)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
        })
        .collect();

    let recalled = planted.intersection(&found_paths).count();
    assert_eq!(
        recalled,
        planted.len(),
        "RECALL: only {}/{} planted AWS keys surfaced, the large-tree scan dropped files \
         from the backpressured tail (a faster-but-lossy scan is not a valid result). \
         Missing example: {:?}",
        recalled,
        planted.len(),
        planted.difference(&found_paths).next(),
    );
}
