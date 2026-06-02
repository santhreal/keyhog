//! Contract: `--format html` emits well-formed HTML5 with DOCTYPE and required structure.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_format_html_valid_doctype() {
    let (_dir, path) = write_temp_file("clean.txt", "plaintext\n");
    let output = Command::new(binary())
        .args(["scan", "--no-daemon", "--format", "html"])
        .arg(&path)
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&output.stdout);

    // HTML5 DOCTYPE must be present at the start
    assert!(
        stdout.starts_with("<!DOCTYPE html>"),
        "html must start with <!DOCTYPE html>; got: {:.60}",
        stdout
    );

    // Verify core structural elements
    assert!(stdout.contains("<html"), "html must contain <html tag");
    assert!(
        stdout.contains("<head>"),
        "html must contain <head> section"
    );
    assert!(
        stdout.contains("<body>"),
        "html must contain <body> section"
    );
    assert!(
        stdout.contains("</html>"),
        "html must end with closing </html> tag"
    );

    // Verify the theme attribute and title set by HtmlReporter
    assert!(
        stdout.contains("data-theme="),
        "html must specify a data-theme attribute"
    );
    assert!(
        stdout.contains("KeyHog Secret Scan Report"),
        "html must have the expected page title"
    );

    // Verify embedded JavaScript presence (findings data injection)
    assert!(
        stdout.contains("<script>"),
        "html must include a <script> section"
    );
    assert!(
        stdout.contains("const rawFindings"),
        "html must inject rawFindings constant for the UI"
    );
}
