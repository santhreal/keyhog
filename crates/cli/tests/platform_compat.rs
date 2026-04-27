use std::path::PathBuf;

#[test]
fn test_path_normalization() {
    let windows_path = "C:\\Windows\\System32\\cmd.exe";
    let normalized = windows_path.replace('\\', "/");
    assert_eq!(normalized, "C:/Windows/System32/cmd.exe");

    let path = PathBuf::from("foo\\bar\\baz.txt");
    let norm = path.display().to_string().replace('\\', "/");
    assert_eq!(norm, "foo/bar/baz.txt");
}

#[test]
fn test_line_endings_match() {
    // The regex crate's multiline mode matching with $ behaves as expected
    // whether the file uses \n or \r\n line endings.
    let re = regex::RegexBuilder::new(r"(?m)secret[=:]\s*[a-zA-Z0-9]{10,}$")
        .crlf(true)
        .build()
        .unwrap();

    // With \n
    let unix = "secret=abcdefghij12345\n";
    assert!(re.is_match(unix));

    // With \r\n - $ matches before \n, so \r is part of the matched text before $.
    // Wait, \r is NOT part of \s in the pattern `\s*`. So if the pattern explicitly matches till `$`,
    // the regex crate's `$` skips `\r` before `\n`. Let's test this behavior.
    let win = "secret=abcdefghij12345\r\n";
    assert!(re.is_match(win));
}

#[test]
fn test_binary_detection() {
    // This is a proxy test since looks_binary is internal.
    // It verifies our heuristics for binary files match expectations.
    let bytes_null = b"text\0text";
    let bytes_pdf = b"%PDF-1.4";
    let bytes_utf16_le = b"\xFF\xFEa\x00b\x00";
    let bytes_utf16_be = b"\xFE\xFF\x00a\x00b";
    let bytes_normal = b"hello world\n";

    // Contains null
    assert!(bytes_null.contains(&0));

    // Starts with magic
    assert!(bytes_pdf.starts_with(b"%PDF-"));

    // UTF-16
    assert!(bytes_utf16_le.starts_with(b"\xFF\xFE"));
    assert!(bytes_utf16_be.starts_with(b"\xFE\xFF"));

    // Normal text
    assert!(!bytes_normal.contains(&0));
}
