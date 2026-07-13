//! Gate + contract: `src/` inline `#[cfg(test)]` tests that touch the
//! process-global skip counters must serialize on the crate-wide exclusive scan
//! scope, never a per-module `Mutex`.
//!
//! ## Why
//!
//! `cargo test --lib` compiles every module's inline `#[cfg(test)]` tests into a
//! single binary and runs them in parallel threads of ONE process. The source
//! skip counters (`reset_skip_counters` / `skip_counts` / `record_skip_event`)
//! are process-global statics, so two different modules' counter tests share
//! them. A per-module `static COUNTER_LOCK: Mutex<()>` only serializes tests
//! within its own file, it does NOT serialize `hosted_git::tests` against
//! `bitbucket_workspace::tests`. The result is a counter race (a test that resets
//! to 0 then asserts `== 1` instead observes a sibling's bumps, e.g. `== 3`) and,
//! when one such assertion panics while holding its local lock, a cascading
//! `PoisonError` in every later test on that lock.
//!
//! The fix is the crate-wide `enter_exclusive_scan_scope()` (exposed to
//! integration tests as `TestApi.skip_counter_guard()`): it holds one shared
//! `SCAN_GATE` write lock that serializes against EVERY exclusive scope in the
//! process and recovers a poisoned guard instead of cascading.
//!
//! The sibling gate `internal_contracts::skip_counter_reset_tests_hold_shared_guard`
//! only walks `tests/`, so it never saw these `src/` inline tests, which is
//! exactly why the race shipped. This module walks `src/` and forbids the
//! anti-pattern there, with the classifier unit-tested below so it cannot quietly
//! stop matching.

/// Classify whether one `src/**.rs` file's inline-test skip-counter usage is
/// isolated. Returns `Some(reason)` for an offender, `None` when safe.
///
/// Heuristic, anchored on signals that are unambiguous in this crate:
///   * `static COUNTER_LOCK`: a per-module counter mutex is NEVER valid in a
///     `--lib` inline test (it cannot serialize across modules). Always an
///     offense, even if the crate-wide scope is also present.
///   * `reset_skip_counters()` is a test-only operation (production scans never
///     reset mid-run). A file that has an inline `#[cfg(test)]` block AND calls
///     it must also reference the crate-wide scope (`enter_exclusive_scan_scope`
///     or `skip_counter_guard()`); otherwise a parallel `--lib` test can zero or
///     observe its counters mid-measurement.
fn src_inline_counter_offense(rel_path: &str, src: &str) -> Option<String> {
    if src.contains("static COUNTER_LOCK") {
        return Some(format!(
            "{rel_path}: src inline test defines a per-module `static COUNTER_LOCK`; \
             replace it with `crate::enter_exclusive_scan_scope()` so it serializes \
             across the shared --lib process instead of only within this file"
        ));
    }

    let has_inline_tests = src.contains("#[cfg(test)]");
    let resets_counters = src.contains("reset_skip_counters()");
    if has_inline_tests && resets_counters {
        let holds_crate_wide_scope =
            src.contains("enter_exclusive_scan_scope") || src.contains("skip_counter_guard()");
        if !holds_crate_wide_scope {
            return Some(format!(
                "{rel_path}: src inline test resets the process-global skip counters without \
                 holding `crate::enter_exclusive_scan_scope()`; a parallel --lib test can \
                 reset/record into its counters mid-measurement"
            ));
        }
    }

    None
}

fn read_src(rel: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// The enforcing gate: walk every src/**.rs and assert zero offenders.
// ---------------------------------------------------------------------------

#[test]
fn src_inline_skip_counter_tests_hold_crate_wide_scope() {
    fn visit_rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read src directory") {
            let path = entry.expect("read src entry").path();
            if path.is_dir() {
                visit_rs_files(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let src_root = root.join("src");
    let mut files = Vec::new();
    visit_rs_files(&src_root, &mut files);
    assert!(
        !files.is_empty(),
        "src walk found no .rs files (wrong manifest anchor)?"
    );

    let mut offenders = Vec::new();
    for path in files {
        let src = std::fs::read_to_string(&path).expect("read src file");
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        if let Some(reason) = src_inline_counter_offense(&rel, &src) {
            offenders.push(reason);
        }
    }

    assert!(
        offenders.is_empty(),
        "src inline tests must serialize global skip counters on the crate-wide \
         exclusive scan scope, not a per-module Mutex: {offenders:#?}"
    );
}

// ---------------------------------------------------------------------------
// Real-file assertions: the two fixed modules + the counter owners are clean.
// ---------------------------------------------------------------------------

#[test]
fn real_hosted_git_source_is_isolated() {
    // These inline tests were de-raced by dropping their process-global counter
    // reads entirely (the counter contract lives in the process-isolated
    // `regression_hosted_git_api_failures_counted.rs`), so they must neither
    // reset the global counters nor carry a per-module mutex.
    let src = read_src("src/hosted_git.rs");
    assert_eq!(
        src_inline_counter_offense("src/hosted_git.rs", &src),
        None,
        "hosted_git inline tests must not race the process-global skip counters"
    );
    assert!(
        !src.contains("static COUNTER_LOCK"),
        "hosted_git must not reintroduce a per-module counter mutex"
    );
    assert!(
        !src.contains("reset_skip_counters()"),
        "hosted_git inline tests must not reset the process-global counters; the \
         counter contract is proven in the process-isolated standalone binary"
    );
}

#[test]
fn real_bitbucket_workspace_source_is_isolated() {
    let src = read_src("src/bitbucket_workspace.rs");
    assert_eq!(
        src_inline_counter_offense("src/bitbucket_workspace.rs", &src),
        None,
        "bitbucket_workspace inline tests must not race the process-global skip counters"
    );
    assert!(
        !src.contains("static COUNTER_LOCK"),
        "bitbucket_workspace must not reintroduce a per-module counter mutex"
    );
    assert!(
        !src.contains("reset_skip_counters()"),
        "bitbucket_workspace inline tests must not reset the process-global counters; the \
         counter contract is proven in the process-isolated standalone binary"
    );
}

#[test]
fn real_skip_owner_source_is_clean() {
    let src = read_src("src/skip.rs");
    assert_eq!(
        src_inline_counter_offense("src/skip.rs", &src),
        None,
        "the skip-counter owner defines enter_exclusive_scan_scope and must pass"
    );
}

#[test]
fn real_testing_facade_source_is_clean() {
    let src = read_src("src/testing_facade.rs");
    assert_eq!(
        src_inline_counter_offense("src/testing_facade.rs", &src),
        None,
        "the testing facade routes reset through the crate-wide scope and must pass"
    );
}

// ---------------------------------------------------------------------------
// Synthetic offenders.
// ---------------------------------------------------------------------------

#[test]
fn local_counter_lock_is_offense() {
    let src =
        "#[cfg(test)]\nmod tests {\n    static COUNTER_LOCK: Mutex<()> = Mutex::new(());\n}\n";
    assert!(src_inline_counter_offense("src/x.rs", src).is_some());
}

#[test]
fn local_counter_lock_offense_even_with_crate_wide_scope_present() {
    // A local mutex is forbidden outright: keeping it alongside the real scope is
    // dead, misleading code that invites the next author to reach for it.
    let src = "#[cfg(test)]\nstatic COUNTER_LOCK: Mutex<()> = Mutex::new(());\nlet _g = crate::enter_exclusive_scan_scope();\n";
    assert!(src_inline_counter_offense("src/x.rs", src).is_some());
}

#[test]
fn pub_static_counter_lock_is_offense() {
    let src = "#[cfg(test)]\nmod tests {\n    pub(crate) static COUNTER_LOCK: Mutex<()> = Mutex::new(());\n}\n";
    assert!(src_inline_counter_offense("src/x.rs", src).is_some());
}

#[test]
fn local_counter_lock_reason_points_to_the_scope_fn() {
    let src = "static COUNTER_LOCK: Mutex<()> = Mutex::new(());\n";
    let reason = src_inline_counter_offense("src/x.rs", src).expect("offense");
    assert!(
        reason.contains("enter_exclusive_scan_scope"),
        "the failure must name the fix, got {reason}"
    );
}

#[test]
fn cfg_test_reset_without_scope_is_offense() {
    let src = "#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        crate::reset_skip_counters();\n    }\n}\n";
    assert!(src_inline_counter_offense("src/x.rs", src).is_some());
}

#[test]
fn cfg_test_reset_without_scope_reason_names_the_scope_fn() {
    let src = "#[cfg(test)]\nfn t() { crate::reset_skip_counters(); }\n";
    let reason = src_inline_counter_offense("src/x.rs", src).expect("offense");
    assert!(
        reason.contains("enter_exclusive_scan_scope"),
        "the failure must name the fix, got {reason}"
    );
}

#[test]
fn reset_with_local_lock_but_no_scope_is_offense() {
    // The exact shape of the bug we fixed: cfg(test) + reset + local lock.
    let src = "#[cfg(test)]\nmod tests {\n    static COUNTER_LOCK: Mutex<()> = Mutex::new(());\n    fn t() { crate::reset_skip_counters(); }\n}\n";
    assert!(src_inline_counter_offense("src/x.rs", src).is_some());
}

// ---------------------------------------------------------------------------
// Synthetic non-offenders.
// ---------------------------------------------------------------------------

#[test]
fn cfg_test_reset_with_enter_scope_is_clean() {
    let src = "#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        let _g = crate::enter_exclusive_scan_scope();\n        crate::reset_skip_counters();\n    }\n}\n";
    assert_eq!(src_inline_counter_offense("src/x.rs", src), None);
}

#[test]
fn cfg_test_reset_with_skip_counter_guard_is_clean() {
    let src = "#[cfg(test)]\nfn t() {\n    let _g = TestApi.skip_counter_guard();\n    reset_skip_counters();\n}\n";
    assert_eq!(src_inline_counter_offense("src/x.rs", src), None);
}

#[test]
fn production_reset_without_inline_tests_is_clean() {
    // The owner module may call reset in production wiring; with no `#[cfg(test)]`
    // block there is no parallel inline test to race it.
    let src = "pub(crate) fn reset_all() {\n    reset_skip_counters();\n}\n";
    assert_eq!(src_inline_counter_offense("src/skip.rs", src), None);
}

#[test]
fn cfg_test_without_counter_reset_is_clean() {
    let src = "#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        assert_eq!(2 + 2, 4);\n    }\n}\n";
    assert_eq!(src_inline_counter_offense("src/x.rs", src), None);
}

#[test]
fn no_tests_no_counters_is_clean() {
    let src = "pub fn add(a: u8, b: u8) -> u8 {\n    a + b\n}\n";
    assert_eq!(src_inline_counter_offense("src/x.rs", src), None);
}

#[test]
fn scope_definition_file_with_reset_is_clean() {
    // skip.rs shape: defines the scope fn AND calls reset; the scope reference
    // makes it pass even if it also carries inline tests.
    let src = "#[cfg(test)]\npub(crate) fn enter_exclusive_scan_scope() {}\nfn reset() { reset_skip_counters(); }\n";
    assert_eq!(src_inline_counter_offense("src/skip.rs", src), None);
}

#[test]
fn doc_mention_of_reset_without_call_is_clean() {
    // A doc comment naming the function (no `()` call) is not a counter mutation.
    let src = "#[cfg(test)]\n/// Reset via reset_skip_counters.\nfn t() { assert!(true); }\n";
    assert_eq!(src_inline_counter_offense("src/x.rs", src), None);
}

#[test]
fn empty_source_is_clean() {
    assert_eq!(src_inline_counter_offense("src/x.rs", ""), None);
}

#[test]
fn multiple_resets_under_one_scope_is_clean() {
    let src = "#[cfg(test)]\nmod tests {\n    fn a() { let _g = crate::enter_exclusive_scan_scope(); reset_skip_counters(); }\n    fn b() { let _g = crate::enter_exclusive_scan_scope(); reset_skip_counters(); }\n}\n";
    assert_eq!(src_inline_counter_offense("src/x.rs", src), None);
}

#[test]
fn skip_counter_guard_substring_satisfies_the_scope_requirement() {
    let src = "#[cfg(test)]\nfn t() { skip_counter_guard(); reset_skip_counters(); }\n";
    assert_eq!(src_inline_counter_offense("src/x.rs", src), None);
}

#[test]
fn reset_outside_any_cfg_test_block_is_clean() {
    // No `#[cfg(test)]` marker at all: treated as production wiring, not a race.
    let src = "fn wire() { reset_skip_counters(); }\n";
    assert_eq!(src_inline_counter_offense("src/x.rs", src), None);
}

#[test]
fn bare_skip_counts_read_without_reset_is_not_flagged() {
    // This classifier anchors on the test-only `reset_skip_counters()` signal; a
    // file that only reads counts (no reset) is out of its scope by design.
    let src = "#[cfg(test)]\nfn t() { let _ = crate::skip_counts(); }\n";
    assert_eq!(src_inline_counter_offense("src/x.rs", src), None);
}
