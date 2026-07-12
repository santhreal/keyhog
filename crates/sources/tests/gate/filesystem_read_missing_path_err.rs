//! LR1-A8 replacement gate: keyhog's OWN safe file reader must surface a missing
//! path as `NotFound`. The scan path (`scan_file`) relies on this exact error
//! kind to quietly skip files that vanished between walk and read. The previous
//! body asserted `std::fs::read(...).is_err()` — that tests the standard library,
//! not keyhog, and would pass no matter how `read_file_safe_bytes` behaved.

use std::io::ErrorKind;
use std::path::Path;

use keyhog_sources::read_file_safe_bytes;

#[test]
fn read_missing_path_returns_not_found() {
    let err = read_file_safe_bytes(Path::new("/nonexistent/keyhog-gate-path"), 1 << 20)
        .expect_err("reading a missing path through keyhog's safe reader must fail");
    assert_eq!(
        err.kind(),
        ErrorKind::NotFound,
        "keyhog's safe reader must surface a missing path as NotFound (scan_file depends on it), got {err:?}"
    );
}
