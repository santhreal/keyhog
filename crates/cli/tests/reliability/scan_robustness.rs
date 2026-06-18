//! Hostile scan inputs. A secret scanner is pointed at whatever is on disk -
//! binary blobs, NUL bytes, symlink loops, emoji filenames, multi-megabyte
//! single lines. None of it may panic, hang, or crash. Hangs are bounded and
//! count as failures (a hang is the worst customer experience).

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

use crate::reliability::harness::binary;

/// Run `keyhog scan <args>` with a wall-clock bound. Returns `(code, timed_out)`.
/// A timeout means keyhog hung on the input - a defect, surfaced as `timed_out`.
fn scan_bounded(path: &Path, extra: &[&str], secs: u64) -> (Option<i32>, bool) {
    let mut args: Vec<String> = vec!["scan".into(), "--no-daemon".into()];
    for e in extra {
        args.push((*e).into());
    }
    args.push(path.to_string_lossy().into_owned());
    let mut child = Command::new(binary())
        .args(&args)
        .env("KEYHOG_RELEASE_API_BASE", "http://127.0.0.1:9")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn keyhog scan");
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return (status.code(), false);
        }
        if start.elapsed() > Duration::from_secs(secs) {
            let _ = child.kill();
            let _ = child.wait();
            return (None, true);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn assert_handled(path: &Path, extra: &[&str], secs: u64, what: &str) {
    let (code, timed_out) = scan_bounded(path, extra, secs);
    assert!(!timed_out, "{what}: keyhog HUNG (> {secs}s) on this input");
    assert!(code.is_some(), "{what}: keyhog crashed (killed by signal)");
    let c = code.unwrap();
    assert!(
        documented_scan_exit(c),
        "{what}: undocumented/abnormal exit {c}"
    );
}

fn documented_scan_exit(code: i32) -> bool {
    keyhog::exit_codes::DEFINITIONS
        .iter()
        .any(|definition| definition.scan_reachable && i32::from(definition.code) == code)
}

#[test]
fn empty_file() {
    let d = TempDir::new().unwrap();
    let p = d.path().join("empty.txt");
    std::fs::write(&p, b"").unwrap();
    assert_handled(&p, &["--format", "json"], 30, "empty file");
}

#[test]
fn all_nul_bytes() {
    let d = TempDir::new().unwrap();
    let p = d.path().join("nul.bin");
    std::fs::write(&p, vec![0u8; 64 * 1024]).unwrap();
    assert_handled(&p, &["--format", "json"], 30, "all-NUL file");
}

#[test]
fn invalid_utf8_bytes() {
    let d = TempDir::new().unwrap();
    let p = d.path().join("bad.bin");
    std::fs::write(&p, vec![0xC0, 0xC1, 0xF5, 0xFF, 0xFE, 0x80, 0x81]).unwrap();
    assert_handled(&p, &["--format", "json"], 30, "invalid UTF-8");
}

#[test]
fn random_binary_blob() {
    let d = TempDir::new().unwrap();
    let p = d.path().join("blob.bin");
    let bytes: Vec<u8> = (0..256u32)
        .flat_map(|i| (i as u8).wrapping_mul(31).to_le_bytes())
        .cycle()
        .take(512 * 1024)
        .collect();
    std::fs::write(&p, bytes).unwrap();
    assert_handled(&p, &["--format", "json"], 30, "random binary blob");
}

#[test]
fn one_huge_line() {
    let d = TempDir::new().unwrap();
    let p = d.path().join("huge.txt");
    std::fs::write(&p, "A".repeat(4 * 1024 * 1024)).unwrap();
    assert_handled(&p, &["--format", "json"], 60, "4MB single line");
}

#[test]
fn millions_of_short_lines() {
    let d = TempDir::new().unwrap();
    let p = d.path().join("lines.txt");
    let body = "x\n".repeat(500_000);
    std::fs::write(&p, body).unwrap();
    assert_handled(&p, &["--format", "json"], 60, "500k short lines");
}

#[test]
fn crlf_line_endings() {
    let d = TempDir::new().unwrap();
    let p = d.path().join("crlf.txt");
    std::fs::write(
        &p,
        "line one\r\nAWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\r\n",
    )
    .unwrap();
    assert_handled(&p, &["--format", "json"], 30, "CRLF file");
}

#[test]
fn utf8_bom_prefix() {
    let d = TempDir::new().unwrap();
    let p = d.path().join("bom.txt");
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(b"AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n");
    std::fs::write(&p, bytes).unwrap();
    assert_handled(&p, &["--format", "json"], 30, "UTF-8 BOM file");
}

#[test]
fn emoji_and_unicode_filename() {
    let d = TempDir::new().unwrap();
    let p = d.path().join("secret-🔑-café-日本語.env");
    std::fs::write(&p, "API=clean\n").unwrap();
    assert_handled(&p, &["--format", "json"], 30, "emoji/unicode filename");
}

#[test]
fn very_long_filename() {
    let d = TempDir::new().unwrap();
    let name = format!("{}.txt", "a".repeat(200));
    let p = d.path().join(name);
    std::fs::write(&p, "clean\n").unwrap();
    assert_handled(&p, &["--format", "json"], 30, "200-char filename");
}

#[test]
fn dev_null_as_path() {
    assert_handled(
        Path::new("/dev/null"),
        &["--format", "json"],
        30,
        "/dev/null",
    );
}

#[test]
fn deeply_nested_directories() {
    let d = TempDir::new().unwrap();
    let mut path = d.path().to_path_buf();
    for i in 0..40 {
        path = path.join(format!("dir{i}"));
    }
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(path.join("deep.txt"), "clean\n").unwrap();
    assert_handled(
        d.path(),
        &["--format", "json"],
        60,
        "40-deep directory tree",
    );
}

#[test]
fn symlink_loop_does_not_hang() {
    // A directory symlink pointing back at its ancestor: a naive walker loops
    // forever. keyhog must detect the cycle. Bounded so a hang fails fast.
    let d = TempDir::new().unwrap();
    let sub = d.path().join("a").join("b");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(d.path().join("a").join("file.txt"), "clean\n").unwrap();
    let link = sub.join("loop");
    if std::os::unix::fs::symlink(d.path().join("a"), &link).is_ok() {
        assert_handled(d.path(), &["--format", "json"], 30, "symlink loop");
    }
}

#[test]
fn filename_that_looks_like_a_flag_via_separator() {
    // `scan -- --output` must treat `--output` as a path, not a flag.
    let d = TempDir::new().unwrap();
    let weird = d.path().join("--output");
    std::fs::write(&weird, "clean\n").unwrap();
    let (code, timed_out) = scan_bounded(&weird, &["--format", "json", "--"], 30);
    // The `--` is appended before the path by scan_bounded's arg builder? No -
    // build explicitly here instead.
    let _ = (code, timed_out);
    let out = Command::new(binary())
        .args(["scan", "--no-daemon", "--format", "json", "--"])
        .arg(&weird)
        .env("KEYHOG_RELEASE_API_BASE", "http://127.0.0.1:9")
        .output()
        .unwrap();
    assert!(
        out.status.code().is_some(),
        "scanning a file named --output crashed"
    );
    assert!(
        documented_scan_exit(out.status.code().unwrap()),
        "scanning a flag-like filename gave abnormal exit {:?}",
        out.status.code()
    );
}

#[test]
fn unreadable_directory_is_skipped_not_fatal() {
    use std::os::unix::fs::PermissionsExt;
    let d = TempDir::new().unwrap();
    let readable = d.path().join("readable.txt");
    std::fs::write(&readable, "clean\n").unwrap();
    let locked = d.path().join("locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::write(locked.join("inside.txt"), "clean\n").unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

    let (code, timed_out) = scan_bounded(d.path(), &["--format", "json"], 30);

    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert!(!timed_out, "scan hung on an unreadable subdir");
    assert!(
        code.is_some() && documented_scan_exit(code.unwrap()),
        "an unreadable subdir should warn-and-continue, got {code:?}"
    );
}
