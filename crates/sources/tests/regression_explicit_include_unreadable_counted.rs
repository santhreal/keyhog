//! Law 10 regression: an explicitly `--include`'d path that cannot be read —
//! it does not exist, is neither a file nor a directory, or its `stat` fails —
//! must be COUNTED as unreadable and surfaced as a source error, never silently
//! dropped. Before this fix the include walk returned an empty iterator for
//! such a path, so the file vanished from the scan set while the run still
//! printed "0 secrets" — a false clean bill of health for a file the user
//! explicitly named.
//!
//! Own test binary: `skip_counts()` reads process-global atomics, so this is
//! isolated from the parallel integration pool and can assert exact counts.

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};

#[test]
fn explicitly_included_unreadable_path_is_counted_not_silently_dropped() {
    let dir = tempfile::tempdir().expect("tempdir");

    // An explicitly-included path that does not exist: `canonicalize` fails so
    // the original path is kept, and it is then neither a file nor a directory,
    // hitting the include walk's `else` arm. It MUST bump the unreadable count
    // and emit a visible source error.
    TestApi.reset_skip_counters();
    let missing = dir.path().join("does-not-exist.env");
    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .with_include_paths(vec![missing])
        .chunks()
        .collect();
    assert_eq!(
        rows.len(),
        1,
        "a nonexistent include path must yield one visible source error"
    );
    let err = rows[0]
        .as_ref()
        .expect_err("a nonexistent include path must be an error row");
    assert!(
        err.to_string().contains("explicitly included path")
            && err.to_string().contains("not scanned"),
        "error should name the unscanned explicit include path, got {err}"
    );
    assert_eq!(
        skip_counts().unreadable,
        1,
        "an explicitly --include'd path that cannot be read must be counted as \
         unreadable (Law 10) so `report_skip_summary` surfaces it, instead of the \
         scan silently reporting a clean tree for a file it never read"
    );

    // Negative twin: a real, readable included file is scanned and must NOT be
    // counted as unreadable (no false coverage-gap alarm on healthy files).
    TestApi.reset_skip_counters();
    let real = dir.path().join("real.env");
    std::fs::write(&real, b"AWS=AKIAQYLPMN5HFIQR7XYA\n").expect("write");
    let bodies: Vec<String> = FilesystemSource::new(dir.path().to_path_buf())
        .with_include_paths(vec![real])
        .chunks()
        .flatten()
        .map(|c| c.data.to_string())
        .collect();
    assert!(
        bodies.iter().any(|b| b.contains("AKIAQYLPMN5HFIQR7XYA")),
        "a real included file must still be scanned; got {bodies:?}"
    );
    assert_eq!(
        skip_counts().unreadable,
        0,
        "a readable included file must NOT be counted as unreadable"
    );
}
