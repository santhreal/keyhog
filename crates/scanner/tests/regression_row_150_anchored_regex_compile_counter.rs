//! Row 150 regression test: instrument all anchored regex compilation paths
//! to tick `LAZY_REGEX_COMPILE_EVENTS` runtime counters, and prove zero recompiles
//! during steady-state warm scanner operations.

mod support;

use keyhog_core::Chunk;
use keyhog_scanner::testing::{
    anchored_regex_capture_for_test, lazy_regex_compile_events,
};
use keyhog_scanner::CompiledScanner;
use std::sync::LazyLock;
use support::contracts::{make_chunk, scanner};

const CHILD_ENV: &str = "KEYHOG_ROW_150_COMPILE_COUNTER_CHILD";

fn run_isolated_counter_test() -> bool {
    if std::env::var_os(CHILD_ENV).is_some() {
        return false;
    }
    let test_name = std::thread::current()
        .name()
        .expect("test thread has a name")
        .to_owned();
    let output = std::process::Command::new(
        std::env::current_exe().expect("current scanner test executable is available"),
    )
    .env(CHILD_ENV, "1")
    .arg(&test_name)
    .arg("--exact")
    .arg("--test-threads=1")
    .output()
    .expect("isolated compile-event test process starts");
    assert!(
        output.status.success(),
        "isolated compile-event test `{test_name}` failed with output: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    true
}

fn primed_scanner() -> &'static CompiledScanner {
    static S: LazyLock<CompiledScanner> = LazyLock::new(|| {
        let s = scanner();
        s.warm();
        s
    });
    &S
}

fn chunk(text: &str) -> Chunk {
    make_chunk(text, "filesystem", "row_150_test.txt")
}

#[test]
fn dynamic_anchored_regex_compile_ticks_counter_and_caches_warm() {
    if run_isolated_counter_test() {
        return;
    }

    let pattern = "KH_ROW150_TEST_SECRET_[A-Z0-9]{16}";
    let before = lazy_regex_compile_events();

    // 1. Direct compilation without left-context (at position 0)
    let capture0 = anchored_regex_capture_for_test(
        pattern,
        false,
        false,
        "KH_ROW150_TEST_SECRET_0123456789ABCDEF",
    );
    assert_eq!(capture0, Some((0, 38)));
    let after_first = lazy_regex_compile_events();
    assert_eq!(
        after_first,
        before + 1,
        "first no-context anchored compile must tick the compile counter by 1"
    );

    // 2. Direct compilation with left-context (at position > 0)
    let capture_ctx = anchored_regex_capture_for_test(
        pattern,
        false,
        true,
        "XKH_ROW150_TEST_SECRET_0123456789ABCDEF",
    );
    assert_eq!(capture_ctx, Some((0, 39)));
    let after_second = lazy_regex_compile_events();
    assert_eq!(
        after_second,
        after_first + 1,
        "first left-context anchored compile must tick the compile counter by 1"
    );
}

#[test]
fn warm_scanner_anchored_detection_recompiles_zero() {
    if run_isolated_counter_test() {
        return;
    }

    let s = primed_scanner();

    // Sample inputs that hit anchored localization paths in phase-2 and confirmed passes
    let samples = [
        "AWS_KEY=AKIAZ7QH4XNB2WKLP3RV secret=wJalrXUtnFEMI7K8MDENGbPxRfiCYEXKEYAAAA",
        "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB",
        "glpat-Ab3Cd6Ef9Gh2Ij5Kl8Mn",
        "sk_live_0123456789abcdefghijklmnopqrstuv",
        "xoxb-012345678901-0123456789012-abcdefghijklmnopqrstuvwx",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0\n-----END RSA PRIVATE KEY-----\n",
    ];

    // Prime the sample chunks through the scanner (cold pass)
    for sample in &samples {
        let c = chunk(sample);
        s.clear_fragment_cache();
        let _ = s.scan(&c);
    }

    // Capture the baseline counter after all sample patterns have been touched
    let baseline = lazy_regex_compile_events();

    // Run 20 rounds of re-scanning over all primed chunks (warm pass)
    for _ in 0..20 {
        for sample in &samples {
            let c = chunk(sample);
            s.clear_fragment_cache();
            let _ = s.scan(&c);
        }
    }

    let final_count = lazy_regex_compile_events();
    assert_eq!(
        final_count,
        baseline,
        "steady-state scanning over primed anchored patterns must not trigger recompilations (delta: {})",
        final_count - baseline
    );
}

#[test]
fn warm_is_idempotent_and_steady_state_across_rescan_cycles() {
    if run_isolated_counter_test() {
        return;
    }

    let s = primed_scanner();
    let before = lazy_regex_compile_events();
    s.warm();
    s.warm();
    let after = lazy_regex_compile_events();
    assert_eq!(
        after, before,
        "redundant warm() invocations must recompile zero regexes"
    );

    let test_chunk = chunk("plain text with no secrets but some structural code: if (x == 42) { return; }");
    s.clear_fragment_cache();
    let _ = s.scan(&test_chunk);

    let snap = lazy_regex_compile_events();
    for _ in 0..10 {
        s.clear_fragment_cache();
        let _ = s.scan(&test_chunk);
    }
    assert_eq!(
        lazy_regex_compile_events(),
        snap,
        "repeated inert scans must not advance compile counters"
    );
}
