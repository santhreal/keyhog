//! CLI terminal palette TTY / NO_COLOR resolution.

use std::fs;
use std::path::{Path, PathBuf};

#[path = "../../src/style.rs"]
mod style;

use style::{
    fail, for_stderr, for_stdout, info, no_color_from_env, pass, terminal_clear_line_prefix,
    terminal_palette, warn, write_diagnostic_finding,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn collect_rs_files(root: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(root)
        .unwrap_or_else(|error| panic!("read source directory {}: {error}", root.display()));
    for entry in entries {
        let entry = entry
            .unwrap_or_else(|error| panic!("read dir entry under {}: {error}", root.display()));
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn read_source(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read production source {}: {error}", path.display()))
}

#[test]
fn color_only_on_tty_without_no_color() {
    let palette = terminal_palette(true, false);
    assert_eq!(palette.green, "\x1b[32m");
    assert_eq!(palette.reset, "\x1b[0m");
}

#[test]
fn no_color_forces_plain_even_on_a_tty() {
    assert_eq!(terminal_palette(true, true).green, "");
}

// no-color.org contract: disable color ONLY when NO_COLOR is present AND
// non-empty. Exercised on the pure predicate so no process-global env is
// mutated (unit tests share one process and run in parallel).
#[test]
fn no_color_from_env_follows_presence_and_nonempty_rule() {
    use std::ffi::OsStr;
    assert!(
        !no_color_from_env(None),
        "unset NO_COLOR must keep color enabled"
    );
    assert!(
        !no_color_from_env(Some(OsStr::new(""))),
        "empty NO_COLOR= must NOT disable color (spec: present AND non-empty)"
    );
    assert!(
        no_color_from_env(Some(OsStr::new("1"))),
        "NO_COLOR=1 disables color"
    );
    assert!(
        no_color_from_env(Some(OsStr::new("0"))),
        "any non-empty value disables color, regardless of the value"
    );
    assert!(
        no_color_from_env(Some(OsStr::new("false"))),
        "even NO_COLOR=false disables color: the convention ignores the value once non-empty"
    );
}

#[test]
fn non_tty_is_plain() {
    // The common pipe/redirect case: `keyhog doctor > out.txt` must not
    // embed escape sequences.
    let palette = terminal_palette(false, false);
    assert_eq!(palette.green, "");
    assert_eq!(palette.reset, "");
}

#[test]
fn clear_line_prefix_tracks_tty_status() {
    assert_eq!(terminal_clear_line_prefix(true), "\x1b[2K\r");
    assert_eq!(terminal_clear_line_prefix(false), "");
}

#[test]
fn status_helpers_wrap_labels_with_palette_color() {
    let palette = terminal_palette(true, false);

    assert_eq!(pass("PASS", &palette), "\x1b[32mPASS\x1b[0m");
    assert_eq!(fail("FAIL", &palette), "\x1b[31mFAIL\x1b[0m");
    assert_eq!(warn("WARN", &palette), "\x1b[33mWARN\x1b[0m");
    assert_eq!(info("INFO", &palette), "\x1b[36mINFO\x1b[0m");
}

#[test]
fn stdout_and_stderr_palette_helpers_are_callable() {
    let stdout = for_stdout();
    let stderr = for_stderr();

    for palette in [stdout, stderr] {
        assert!(
            palette.reset.is_empty() || palette.reset == "\x1b[0m",
            "palette helper returned an unexpected reset sequence"
        );
    }
}

#[test]
fn write_diagnostic_finding_with_confidence_and_line() {
    let mut buf = Vec::new();
    write_diagnostic_finding(
        &mut buf,
        "FINDING",
        "detector_1",
        "src/main.rs",
        Some(42),
        keyhog_core::Severity::Critical,
        Some(0.95),
        "redacted_secret",
    )
    .expect("diagnostic finding should write to in-memory buffer");
    let s = String::from_utf8(buf).expect("diagnostic output must be utf-8");
    assert_eq!(
        s,
        "FINDING detector_1 src/main.rs:42 CRITICAL (0.95)  redacted_secret\n"
    );
}

#[test]
fn write_diagnostic_finding_no_confidence_no_line() {
    let mut buf = Vec::new();
    write_diagnostic_finding(
        &mut buf,
        "WATCH",
        "detector_2",
        "src/lib.rs",
        None,
        keyhog_core::Severity::Medium,
        None,
        "redacted_other",
    )
    .expect("diagnostic finding should write to in-memory buffer");
    let s = String::from_utf8(buf).expect("diagnostic output must be utf-8");
    assert_eq!(s, "WATCH detector_2 src/lib.rs MEDIUM  redacted_other\n");
}

#[test]
fn production_terminal_surfaces_do_not_bypass_shared_palette() {
    let root = repo_root();
    let mut rust_files = Vec::new();
    collect_rs_files(&root.join("crates/cli/src"), &mut rust_files);
    collect_rs_files(&root.join("crates/core/src"), &mut rust_files);

    let banned_rust_fragments = [
        ("raw ANSI escape literal", r"\x1b["),
        ("legacy local colorizer", "colorize("),
        ("old public CLI style facade", "pub mod style"),
        ("old public CLI style path", "keyhog::style"),
        ("escaped check-mark status glyph", r"\u{2714}"),
        ("escaped cross status glyph", r"\u{2716}"),
        ("escaped status emoji", r"\u{1F500}"),
        ("check-mark status glyph", "\u{2713}"),
        ("cross status glyph", "\u{2717}"),
        ("warning status glyph", "\u{26a0}"),
        ("white-check status emoji", "\u{2705}"),
        ("lock status emoji", "\u{1f512}"),
        ("sparkle status emoji", "\u{2728}"),
        ("gear status glyph", "\u{2699}"),
        ("magnifier status emoji", "\u{1f50d}"),
        ("clipboard status emoji", "\u{1f4cb}"),
        ("document status emoji", "\u{1f4c4}"),
    ];

    let mut offenders = Vec::new();
    for path in rust_files {
        let rel = path
            .strip_prefix(&root)
            .unwrap_or_else(|error| panic!("strip repo root from {}: {error}", path.display()))
            .to_string_lossy()
            .replace('\\', "/");
        if rel == "crates/core/src/report/style.rs" || rel == "crates/cli/src/style.rs" {
            continue;
        }
        let src = read_source(&path);
        for (reason, fragment) in banned_rust_fragments {
            if src.contains(fragment) {
                offenders.push(format!("{rel}: {reason} `{fragment}`"));
            }
        }
    }

    let install_sh = read_source(&root.join("install.sh"));
    for required in [
        "info() { status INFO",
        "ok()   { status PASS",
        "warn() { status WARN",
        "err()  { status_err FAIL",
        "PASS %s (%sms)",
        "FAIL %s (%sms)",
    ] {
        if !install_sh.contains(required) {
            offenders.push(format!(
                "install.sh missing shared status contract `{required}`"
            ));
        }
    }
    for old in [" OK (", " FAILED", "OK (%sms)", "FAILED (%sms)"] {
        if install_sh.contains(old) {
            offenders.push(format!(
                "install.sh still uses old status vocabulary `{old}`"
            ));
        }
    }

    let install_ps1 = read_source(&root.join("install.ps1"));
    for required in [
        "function Info { param($t) Write-Status 'INFO'",
        "function Ok   { param($t) Write-Status 'PASS'",
        "function Warn { param($t) Write-Status 'WARN'",
        "function Err  { param($t) Write-Status 'FAIL'",
        "PASS {0} ({1}ms)",
        "FAIL {0} ({1}ms)",
    ] {
        if !install_ps1.contains(required) {
            offenders.push(format!(
                "install.ps1 missing shared status contract `{required}`"
            ));
        }
    }
    for old in [" OK (", " FAILED", "OK ({1}ms)", "FAILED ({1}ms)"] {
        if install_ps1.contains(old) {
            offenders.push(format!(
                "install.ps1 still uses old status vocabulary `{old}`"
            ));
        }
    }

    assert!(
        offenders.is_empty(),
        "terminal/status surfaces must use owned style helpers and PASS/FAIL/WARN/INFO vocabulary:\n{}",
        offenders.join("\n")
    );
}
