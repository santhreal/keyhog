//! Gate the GPU phase-2 scan path: no `.unwrap(` / `.expect(` in production
//! source lines. The old single `engine/gpu_phase2.rs` was split (commit
//! 78046450) into the files below; this gate now covers the whole set so the
//! no-unwrap contract follows the code instead of a deleted path.

/// `src/engine/`-relative files that together form the GPU phase-2 scan path
/// (region-presence dispatch + GPU stack setup / degrade / cache).
const GPU_SCAN_SRCS: &[&str] = &[
    "gpu_forced.rs",
    "gpu_forced_helpers.rs",
    "gpu_lazy.rs",
    "gpu_lazy_helpers.rs",
    "gpu_literal_scratch.rs",
    "gpu_cache.rs",
    "gpu_region_batch.rs",
    "gpu_region_dispatch.rs",
    "gpu_region_dispatch_helpers.rs",
];

/// Files permitted to contain a co-located `#[cfg(test)]` (or
/// `#[cfg(all(test, ...))]`) module whose lines are excluded from the
/// no-unwrap/expect gate.  These are crate-private modules where white-box
/// inline tests are the correct choice (same rationale as
/// `no_inline_tests_in_src::INLINE_TEST_ALLOWLIST`):
///
/// - `gpu_region_dispatch.rs`: contains crate-private region batching and
///   bounded-validation helpers. Keeping their white-box tests co-located avoids
///   widening the public scanner API for source-only assertions.
const INLINE_TEST_ALLOWLIST: &[&str] = &["gpu_region_dispatch.rs"];

/// Returns `true` when `line` starts a test-cfg annotation that gates an
/// inline test module — either the plain `#[cfg(test)]` form or the
/// compound `#[cfg(all(test, …))]` variant used by GPU-gated modules.
fn is_test_cfg_line(line: &str) -> bool {
    let t = line.trim();
    t == "#[cfg(test)]" || t.starts_with("#[cfg(all(test,") || t.starts_with("#[cfg(all(test ")
}

/// Scan `src` for production `.unwrap(` / `.expect(` usage, skipping lines
/// that are inside an inline test module.  For files in `allowlist` we track
/// brace depth after the first test-cfg annotation and ignore all lines until
/// the test module closes.  For other files the simpler single-line skip still
/// applies.
fn collect_unwrap_offenders(
    rel: &str,
    src: &str,
    allowlist: &[&str],
) -> Vec<(String, usize, String)> {
    let mut offenders = Vec::new();
    let in_allowlist = allowlist.contains(&rel);

    // Depth of open braces inside a `#[cfg(test)]` / `#[cfg(all(test,…))]`
    // module.  0 = not inside a test module.
    let mut test_mod_depth: u32 = 0;
    // Set to true on the line containing the test-cfg attribute; cleared once
    // we see the opening `{` that begins the module body.
    let mut pending_test_mod = false;

    for (i, line) in src.lines().enumerate() {
        let t = line.trim();

        // Always skip comment lines.
        if t.starts_with("//") {
            continue;
        }

        if in_allowlist {
            // Detect entry into a test module.
            if is_test_cfg_line(line) {
                pending_test_mod = true;
                continue;
            }
            if pending_test_mod {
                // Count the opening brace that begins the module body.
                test_mod_depth += t.chars().filter(|&c| c == '{').count() as u32;
                test_mod_depth =
                    test_mod_depth.saturating_sub(t.chars().filter(|&c| c == '}').count() as u32);
                if test_mod_depth > 0 {
                    pending_test_mod = false;
                }
                // This line is part of the test module boundary — skip it.
                continue;
            }
            if test_mod_depth > 0 {
                // Track brace balance inside the test module.
                test_mod_depth += t.chars().filter(|&c| c == '{').count() as u32;
                test_mod_depth =
                    test_mod_depth.saturating_sub(t.chars().filter(|&c| c == '}').count() as u32);
                // Skip: this line is inside the test module.
                continue;
            }
        } else {
            // Legacy single-line skip for `#[cfg(test)]` lines in non-allowlisted files.
            if t.contains("#[cfg(test)]") {
                continue;
            }
        }

        if t.contains(".unwrap(") || t.contains(".expect(") {
            offenders.push((rel.to_string(), i + 1, line.to_string()));
        }
    }
    offenders
}

#[test]
fn engine_scan_gpu_no_unwrap_expect() {
    let base = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/");
    let mut offenders: Vec<(String, usize, String)> = Vec::new();
    for rel in GPU_SCAN_SRCS {
        let path = format!("{base}{rel}");
        let src = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "GPU phase-2 source {rel} not readable ({e}); the file \
                set was renamed - update GPU_SCAN_SRCS to match engine/"
            )
        });
        offenders.extend(collect_unwrap_offenders(rel, &src, INLINE_TEST_ALLOWLIST));
    }
    assert!(
        offenders.is_empty(),
        "GPU phase-2 scan path: unwrap/expect in production source at {:?}",
        offenders.iter().take(5).collect::<Vec<_>>()
    );
}

/// Stale-allowlist guard: each entry in `INLINE_TEST_ALLOWLIST` must still
/// correspond to a file that actually contains a test-cfg annotation.  If a
/// file's inline tests were migrated to an external test file, this guard
/// fires loudly so the exemption cannot silently outlive its reason (Law 9).
#[test]
fn engine_scan_gpu_inline_test_allowlist_not_stale() {
    let base = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/");
    for rel in INLINE_TEST_ALLOWLIST {
        let path = format!("{base}{rel}");
        let src = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "INLINE_TEST_ALLOWLIST entry `{rel}` not readable ({e}); \
                the file was moved — remove it from the allowlist"
            )
        });
        let has_test_cfg = src.lines().any(|line| is_test_cfg_line(line));
        assert!(
            has_test_cfg,
            "stale INLINE_TEST_ALLOWLIST entry `{rel}`: the file no longer \
             contains a #[cfg(test)] / #[cfg(all(test, ...))] annotation — \
             remove it from INLINE_TEST_ALLOWLIST"
        );
    }
}
