//! Regression coverage for the first counter-isolation scope in a test process.

use keyhog_core::Source;
use keyhog_sources::testing::TestApi;
use keyhog_sources::FilesystemSource;

/// A scan that starts before the first counter guard must already hold a shared
/// lease. Otherwise that scan can increment process-global counters while the
/// first counter-asserting test believes it has exclusive ownership.
#[test]
fn scan_started_before_first_counter_guard_blocks_exclusive_scope() {
    let directory = tempfile::tempdir().expect("temporary scan root");
    std::fs::write(directory.path().join("clean.txt"), "clean fixture\n")
        .expect("write scan fixture");

    let source = FilesystemSource::new(directory.path().to_path_buf());
    let scan = source.chunks();
    assert!(
        !TestApi.scan_gate_exclusive_available(),
        "a live scan must hold the shared counter-isolation lease before any guard runs"
    );

    drop(scan);
    let start = std::time::Instant::now();
    let mut available = false;
    while start.elapsed() < std::time::Duration::from_secs(2) {
        if TestApi.scan_gate_exclusive_available() {
            available = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert!(
        available,
        "dropping the scan iterator must release its counter-isolation lease"
    );
}
