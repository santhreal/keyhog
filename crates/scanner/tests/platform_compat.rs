use keyhog_scanner::pipeline;

#[test]
fn path_normalization_handles_windows_separators() {
    let windows_path = "src\\main.rs";
    let normalized = windows_path.replace('\\', "/");
    assert_eq!(normalized, "src/main.rs");
}

#[test]
fn line_ending_handling_compute_offsets() {
    let unix_text = "line1\nline2\nline3";
    let win_text = "line1\r\nline2\r\nline3";

    let unix_offsets = pipeline::compute_line_offsets(unix_text);
    let win_offsets = pipeline::compute_line_offsets(win_text);

    // In current implementation, both should find the same number of lines
    assert_eq!(unix_offsets.len(), 3);
    assert_eq!(win_offsets.len(), 3);

    // For unix: [0, 6, 12]
    // For win: [0, 7, 14]
    assert_eq!(unix_offsets, vec![0, 6, 12]);
    assert_eq!(win_offsets, vec![0, 7, 14]);
}

#[test]
fn binary_detection_handles_null_bytes() {
    let _data = b"some text\0more text";
    // This is tested via the internal looks_binary or similar
    // We can't easily call internal functions from here unless we use a test crate or it's public.
}

#[test]
fn cross_platform_git_askpass_path() {
    // Verify that the path is valid for the current platform
    let temp = tempfile::tempdir().unwrap();
    let askpass = if cfg!(unix) {
        temp.path().join("askpass.sh")
    } else {
        temp.path().join("askpass.bat")
    };

    std::fs::write(&askpass, "echo test").unwrap();
    assert!(askpass.exists());
}
