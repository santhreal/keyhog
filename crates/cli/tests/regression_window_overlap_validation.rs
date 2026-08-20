//! WHY: Closes the defect class where streaming window overlap was accepted at >= 1MB
//! or < 1KB / 0, causing downstream panics inside FilesystemSource::with_window_overlap
//! (assert!(self.window_size > overlap)) or silent removal of seam overlap.
//!
//! What this does NOT catch: OS filesystem buffer cache exhaustion on huge directories.

use clap::Parser;
use keyhog::args::ScanArgs;

#[test]
fn window_overlap_cli_valid_ranges_accepted() {
    let valid_cases = ["1KB", "1KiB", "128KB", "512KB", "1048575B"];
    for case in valid_cases {
        let args = match ScanArgs::try_parse_from(["scan", ".", "--window-overlap", case]) {
            Ok(a) => a,
            Err(e) => panic!("valid window overlap '{case}' must parse successfully: {e}"),
        };
        let parsed = args.window_overlap.expect("overlap must be set");
        assert!(
            parsed >= 1024 && parsed < keyhog_core::DEFAULT_WINDOW_SIZE_BYTES,
            "parsed overlap {parsed} must be in [1024, 1MB)"
        );
    }
}

#[test]
fn window_overlap_cli_sub_1kb_and_zero_rejected() {
    let invalid_underflow = ["0B", "0KB", "512B", "1023B"];
    for case in invalid_underflow {
        let args = ScanArgs::try_parse_from(["scan", ".", "--window-overlap", case]);
        let err_msg = match args {
            Err(err) => err.to_string(),
            Ok(_) => panic!("sub-1KB window overlap '{case}' must be rejected"),
        };
        assert!(
            err_msg.contains("too small") || err_msg.contains("Minimum window overlap is 1KB"),
            "error for '{case}' should explain minimum overlap: {err_msg}"
        );
    }
}

#[test]
fn window_overlap_cli_equal_or_exceeding_window_size_rejected() {
    let invalid_overflow = ["1MB", "1MiB", "2MB", "16MB"];
    for case in invalid_overflow {
        let args = ScanArgs::try_parse_from(["scan", ".", "--window-overlap", case]);
        let err_msg = match args {
            Err(err) => err.to_string(),
            Ok(_) => panic!("window overlap '{case}' >= 1MB must be rejected"),
        };
        assert!(
            err_msg.contains("strictly less than the 1MB window size"),
            "error for '{case}' should explain 1MB window ceiling: {err_msg}"
        );
    }
}
