//! E2E: secrets in UTF-16 (LE and BE, with BOM) files are detected. Windows
//! tooling routinely writes UTF-16 config/log files; a scanner that only reads
//! UTF-8 would silently miss every secret in them - a real cross-platform gap.

use crate::e2e::support::scan_path;
use tempfile::TempDir;

fn utf16_file(dir: &std::path::Path, name: &str, little_endian: bool) -> std::path::PathBuf {
    let text = "token = \"ghp_aB3xK9mZ1qW7rT5vY2nL8pH4jD6sF0gE1cV2\"\n";
    let mut bytes: Vec<u8> = if little_endian {
        vec![0xFF, 0xFE]
    } else {
        vec![0xFE, 0xFF]
    };
    for unit in text.encode_utf16() {
        let pair = if little_endian {
            unit.to_le_bytes()
        } else {
            unit.to_be_bytes()
        };
        bytes.extend_from_slice(&pair);
    }
    let p = dir.join(name);
    std::fs::write(&p, &bytes).unwrap();
    p
}

#[test]
fn detects_secret_in_utf16le_file() {
    let dir = TempDir::new().expect("tempdir");
    let p = utf16_file(dir.path(), "config-le.txt", true);
    let out = scan_path(&p, &[]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "secret in a UTF-16LE file must be found"
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("github_pat"));
}

#[test]
fn detects_secret_in_utf16be_file() {
    let dir = TempDir::new().expect("tempdir");
    let p = utf16_file(dir.path(), "config-be.txt", false);
    let out = scan_path(&p, &[]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "secret in a UTF-16BE file must be found"
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("github_pat"));
}
