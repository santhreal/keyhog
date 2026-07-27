//! KH-1243: borrowed ML source-context ownership, parity, and allocation bounds.

#![cfg(feature = "ml")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;

use keyhog_scanner::ml_scorer::{compute_features_for_detector_with_config, MlCandidateChannel};
use keyhog_scanner::testing::{
    compute_line_offsets, local_context_window, local_context_window_from_offsets,
    ml_context_for_candidate, ml_score_features, queued_ml_features_with_line_offsets,
};
use keyhog_scanner::ScannerConfig;

struct ThreadCountingAlloc;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static ALLOCATED_BYTES: Cell<usize> = const { Cell::new(0) };
}

unsafe impl GlobalAlloc for ThreadCountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        COUNTING.with(|counting| {
            if counting.get() {
                ALLOCATIONS.set(ALLOCATIONS.get() + 1);
                ALLOCATED_BYTES.set(ALLOCATED_BYTES.get() + layout.size());
            }
        });
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        COUNTING.with(|counting| {
            if counting.get() && new_size > layout.size() {
                ALLOCATIONS.set(ALLOCATIONS.get() + 1);
                ALLOCATED_BYTES.set(ALLOCATED_BYTES.get() + new_size - layout.size());
            }
        });
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOCATOR: ThreadCountingAlloc = ThreadCountingAlloc;

fn measure_allocations<T>(run: impl FnOnce() -> T) -> (T, usize, usize) {
    ALLOCATIONS.set(0);
    ALLOCATED_BYTES.set(0);
    COUNTING.set(true);
    let result = run();
    COUNTING.set(false);
    (result, ALLOCATIONS.get(), ALLOCATED_BYTES.get())
}

fn assert_feature_and_score_parity(
    source: &str,
    line_offsets: &[usize],
    line: usize,
    path: Option<&str>,
    credential: &str,
    radius: usize,
    detector_id: &str,
    channel: MlCandidateChannel,
    config: &ScannerConfig,
) {
    let detector = keyhog_core::detector_spec_by_id(detector_id)
        .unwrap_or_else(|| panic!("fixture detector {detector_id:?} must exist"));
    let owned_context = ml_context_for_candidate(source, line, path, radius);
    let expected = compute_features_for_detector_with_config(
        credential,
        &owned_context,
        &config.known_prefixes,
        &config.secret_keywords,
        &config.test_keywords,
        &config.placeholder_keywords,
        detector,
        channel,
    );
    let actual = queued_ml_features_with_line_offsets(
        source,
        line_offsets,
        line,
        path,
        credential,
        radius,
        config,
        detector_id,
        channel == MlCandidateChannel::Entropy,
    );

    assert_eq!(
        actual.map(f32::to_bits),
        expected.map(f32::to_bits),
        "borrowed context changed an exact model feature row"
    );
    assert_eq!(
        ml_score_features(&actual).to_bits(),
        ml_score_features(&expected).to_bits(),
        "borrowed context changed the model score bytes"
    );
}

/// Regression: replacing the owned `file:path\nwindow` string with separate
/// borrows must not change any feature or score bit for positive, negative,
/// Unicode, first-line, or last-line candidates.
#[test]
fn borrowed_context_matches_owned_oracle_for_semantic_and_boundary_cases() {
    let config = ScannerConfig::default();
    let cases = [
        (
            "header\nALCHEMY_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\nfooter",
            2,
            Some("src/alchemy_client.rs"),
            "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
            5,
            "alchemy-api-key",
            MlCandidateChannel::Pattern,
        ),
        (
            "header\nexample_token=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\nfooter",
            2,
            Some("tests/fixtures/mock_config.yaml"),
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            1,
            "generic-secret",
            MlCandidateChannel::Entropy,
        ),
        (
            "πρόλογος\n// 認証情報 для café\nTWILIO_AUTH_TOKEN=0123456789abcdef0123456789abcdef\n終わり",
            3,
            Some("src/認証/café.rs"),
            "0123456789abcdef0123456789abcdef",
            2,
            "twilio-auth-token",
            MlCandidateChannel::Pattern,
        ),
        (
            "CODECOV_TOKEN=0123456789abcdef0123456789abcdef\nsecond\nthird",
            1,
            None,
            "0123456789abcdef0123456789abcdef",
            5,
            "codecov-token",
            MlCandidateChannel::Pattern,
        ),
        (
            "first\nsecond\nPOSTGRES_PASSWORD=hunter2hunter2",
            3,
            Some("deploy/docker-compose.yml"),
            "hunter2hunter2",
            5,
            "generic-password",
            MlCandidateChannel::Entropy,
        ),
    ];

    for (source, line, path, credential, radius, detector_id, channel) in cases {
        let line_offsets = compute_line_offsets(source);
        assert_feature_and_score_parity(
            source,
            &line_offsets,
            line,
            path,
            credential,
            radius,
            detector_id,
            channel,
            &config,
        );
    }
}

/// Regression: path and source remain separate borrows, but model substring
/// predicates must still observe their exact logical `file:{path}\n{window}`
/// boundaries rather than treating each fragment as an isolated context.
#[test]
fn virtual_path_source_boundaries_match_contiguous_context() {
    const CREDENTIAL: &str = "0123456789abcdef0123456789abcdef";
    let mut config = ScannerConfig::default();
    config.secret_keywords = vec![
        "file:src".to_string(),
        "rs\nTWILIO".to_string(),
        ": source".to_string(),
    ];
    config.test_keywords = vec!["context.rs\nTWILIO".to_string()];
    let source = "TWILIO_AUTH_TOKEN=0123456789abcdef0123456789abcdef";
    let line_offsets = compute_line_offsets(source);
    assert_feature_and_score_parity(
        source,
        &line_offsets,
        1,
        Some("src/context.rs"),
        CREDENTIAL,
        0,
        "twilio-auth-token",
        MlCandidateChannel::Pattern,
        &config,
    );
}

/// Regression: context boundary absence is not a literal NUL sentinel. A real
/// NUL next to `=` remains an unquoted assignment, while quote-delimited `=`
/// remains non-assignment, with exact owned/borrowed feature and score parity.
#[test]
fn nul_and_missing_boundaries_preserve_assignment_semantics() {
    const CREDENTIAL: &str = "0123456789abcdef0123456789abcdef";
    let config = ScannerConfig::default();
    for (source, expected_assignment) in [
        ("\0=0123456789abcdef0123456789abcdef", 1.0),
        ("'=' 0123456789abcdef0123456789abcdef", 0.0),
    ] {
        let line_offsets = compute_line_offsets(source);
        assert_feature_and_score_parity(
            source,
            &line_offsets,
            1,
            None,
            CREDENTIAL,
            0,
            "generic-secret",
            MlCandidateChannel::Entropy,
            &config,
        );
        let actual = queued_ml_features_with_line_offsets(
            source,
            &line_offsets,
            1,
            None,
            CREDENTIAL,
            0,
            &config,
            "generic-secret",
            true,
        );
        assert_eq!(actual[16], expected_assignment);
        assert_eq!(actual[39], expected_assignment);
    }
}

/// Regression: dense candidate sets formerly restarted newline discovery from
/// byte zero for every row; every dense row must now use the shared offsets yet
/// remain bit-identical to the owned-context oracle.
#[test]
fn dense_candidates_keep_exact_feature_rows_and_scores() {
    const CREDENTIAL: &str = "0123456789abcdef0123456789abcdef";
    let config = ScannerConfig::default();
    let mut source = String::new();
    for index in 0..128 {
        use std::fmt::Write as _;
        writeln!(source, "TWILIO_AUTH_TOKEN_{index}={CREDENTIAL}")
            .expect("writing to String cannot fail");
    }
    let line_offsets = compute_line_offsets(&source);

    for line in 1..=128 {
        assert_feature_and_score_parity(
            &source,
            &line_offsets,
            line,
            Some("src/dense_twilio.rs"),
            CREDENTIAL,
            5,
            "twilio-auth-token",
            MlCandidateChannel::Pattern,
            &config,
        );
    }
}

/// Regression: a pathological Unicode line and a dense candidate set must not
/// allocate context copies proportional to line size or candidate count; the
/// cached-offset production seam remains allocation-free after one-time model,
/// vocabulary, and thread-scratch initialization, and no borrow escapes its row.
#[test]
fn feature_extraction_is_byte_bounded_and_allocation_free_after_warmup() {
    const CREDENTIAL: &str = "0123456789abcdef0123456789abcdef";
    let config = ScannerConfig::default();
    let source = "€".repeat(200_000);
    let line_offsets = compute_line_offsets(&source);
    let old_window = local_context_window(&source, 1, 5);
    let borrowed_window = local_context_window_from_offsets(&source, &line_offsets, 1, 5);
    assert_eq!(borrowed_window, old_window);
    assert!(borrowed_window.len() <= 8 * 1024);
    assert!(borrowed_window.is_char_boundary(borrowed_window.len()));

    let warm = queued_ml_features_with_line_offsets(
        &source,
        &line_offsets,
        1,
        Some("src/huge_unicode.rs"),
        CREDENTIAL,
        5,
        &config,
        "twilio-auth-token",
        false,
    );
    black_box(ml_score_features(&warm));

    let (retained_row, allocations, allocated_bytes) = measure_allocations(|| {
        let mut last = warm;
        for _ in 0..128 {
            last = queued_ml_features_with_line_offsets(
                &source,
                &line_offsets,
                1,
                Some("src/huge_unicode.rs"),
                CREDENTIAL,
                5,
                &config,
                "twilio-auth-token",
                false,
            );
            black_box(ml_score_features(&last));
        }
        last
    });

    assert_eq!(
        allocations, 0,
        "feature rows allocated {allocated_bytes} bytes"
    );
    assert_eq!(allocated_bytes, 0);
    drop(source);
    assert_eq!(retained_row.map(f32::to_bits), warm.map(f32::to_bits));
    assert!(ml_score_features(&retained_row).is_finite());
}
