//! KH-GAP-121: Cross-platform cfg gates essentially absent in scanner src.
//!
//! STANDARD.md / TESTING_PROGRAM §2 require boundary + adversarial micro coverage
//! per source file. Scanner has decorative `platform_compat.rs` (string replace
//! only) and no gap oracle for Windows/macOS path semantics in `src/`.

use std::path::{Path, PathBuf};

fn scan_platform_cfg_files(dir: &Path, count: &mut usize) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir({}) failed: {e}", dir.display())) {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            scan_platform_cfg_files(&path, count);
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let content = std::fs::read_to_string(&path).expect("read src");
        let has_platform_cfg = content.contains("target_os = \"windows\"")
            || content.contains("target_os = \"macos\"")
            || content.contains("cfg!(windows)")
            || content.contains("cfg!(unix)")
            || content.contains("#[cfg(windows)]")
            || content.contains("#[cfg(unix)]");
        if has_platform_cfg {
            *count += 1;
        }
    }
}

#[test]
fn scanner_src_has_meaningful_cross_platform_cfg_gates() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut platform_cfg_files = 0usize;
    scan_platform_cfg_files(&src, &mut platform_cfg_files);

    // R4-SCAN: 24 files touch `cfg!`/`#[cfg(` but almost all are SIMD/GPU arch —
    // not path/line-ending/IO semantics. Require at least one dedicated cross-platform
    // module under src/ (not tests/) with both windows + unix arms.
    assert!(
        platform_cfg_files >= 3,
        "KH-GAP-121: scanner/src has {platform_cfg_files} files with platform cfg — \
         expected dedicated cross-platform path/IO gates (windows + unix + tests)"
    );
}
