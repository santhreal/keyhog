//! KH-GAP-136: CLI adversarial Windows stubs must not be `assert!(true)` theater.

use std::path::PathBuf;

#[test]
fn adversarial_windows_stubs_contain_real_oracles() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/adversarial");
    let stubs = [
        "unicode_path_scan_windows_stub.rs",
        "pipe_stdout_json_windows_stub.rs",
        "concurrent_four_scans_json_windows_stub.rs",
        "invalid_utf8_filename_windows_stub.rs",
    ];
    for name in stubs {
        let src = std::fs::read_to_string(dir.join(name)).unwrap_or_else(|_| panic!("{name}"));
        assert!(
            !src.contains("assert!(true)"),
            "{name} is a no-op Windows stub; replace with real hostile oracle or SPEC waiver"
        );
    }
}
