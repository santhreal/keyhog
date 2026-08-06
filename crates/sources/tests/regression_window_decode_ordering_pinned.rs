//! Pin the source window and scanner decode working-set ceilings.
//!
//! Filesystem reads use 1 MiB overlap-safe windows. The scanner deliberately
//! keeps a smaller 512 KiB decode ceiling and subdivides each filesystem window
//! again before decode-through. These values therefore bound independent source
//! and decoder working sets; changing either requires preserving bounded decode
//! coverage in the scanner regression paired with this test.

use keyhog_sources::testing::TestApi;

const EXPECTED_WINDOW_SIZE: usize = 1024 * 1024;
const EXPECTED_DECODE_CEILING: usize = 512 * 1024;

#[test]
fn source_and_decode_window_memory_bounds_stay_pinned() {
    let window = TestApi.source_default_window_size();
    let decode_ceiling = keyhog_core::ScanConfig::default().max_decode_bytes;

    assert_eq!(
        window, EXPECTED_WINDOW_SIZE,
        "filesystem source window changed; revalidate scanner bounded decode windows"
    );
    assert_eq!(
        decode_ceiling, EXPECTED_DECODE_CEILING,
        "decode working-set ceiling changed; revalidate encoded midwindow recovery"
    );
    assert!(
        decode_ceiling < window,
        "this contract proves the scanner can decode a source window without raising its memory ceiling"
    );
}
