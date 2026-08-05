//! E2E: `--limit-binary-read-bytes` and `--limit-binary-decompiled-bytes`
//! boundaries.
//!
//! KH-201 / KH-202. Both caps bound how much of a binary KeyHog reads, so an
//! off-by-one or a quiet truncation turns "no secrets in this binary" into a
//! statement about a prefix of the binary. Each is exercised at limit minus
//! one, exactly at the limit, and limit plus one, and every truncation must
//! reach the operator.

#![cfg(feature = "binary")]

use crate::e2e::support::binary;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

/// Two distinct planted keys so a truncated read is visible as a MISSING
/// finding, not just a missing byte.
const HEAD_KEY: &str = "AKIAQYLPMN5HFIQR7XYA";
const TAIL_KEY: &str = "AKIAKPQXRMSNTBVWYZBN";
/// Only ever present in fake decompiler output, so finding it proves the
/// decompiled path ran and losing it proves the cap dropped that path.
const DECOMPILED_KEY: &str = "AKIA2QSVOJXKZ7EUYWTB";

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn scan_binary_target(target: &Path, config: Option<&Path>, extra: &[&str]) -> Output {
    let mut command = Command::new(binary());
    command.args([
        "scan",
        "--daemon=off",
        "--no-suppress-test-fixtures",
        "--show-secrets",
        "--format",
        "jsonl",
    ]);
    if let Some(config) = config {
        command.arg("--config").arg(config);
    }
    command.args(extra).arg("--binary").arg(target);
    command.output().expect("spawn keyhog")
}

/// KH-201. A binary of exactly the cap is read whole; one byte more is read as
/// a prefix and the discarded tail is surfaced, never dropped quietly.
#[test]
fn limit_binary_read_bytes_reads_an_exactly_sized_binary_and_surfaces_a_truncated_one() {
    let dir = TempDir::new().expect("tempdir");
    let target = dir.path().join("fixture.bin");
    // Nul padding on both ends keeps this a binary as far as content sniffing
    // is concerned while leaving two printable runs the strings extractor
    // recovers.
    let body = format!("\0\0AWS_ACCESS_KEY_ID = \"{HEAD_KEY}\"\0\0\0\0AWS_ACCESS_KEY_ID = \"{TAIL_KEY}\"\0\0");
    std::fs::write(&target, &body).expect("write binary fixture");
    let exact = body.len();

    let at_cap = scan_binary_target(
        &target,
        None,
        &["--limit-binary-read-bytes", &format!("{exact}B")],
    );
    let at_cap_stdout = stdout_of(&at_cap);
    let at_cap_stderr = stderr_of(&at_cap);
    assert!(
        at_cap_stdout.contains(HEAD_KEY) && at_cap_stdout.contains(TAIL_KEY),
        "a binary of exactly {exact} bytes must be read whole under a \
         {exact}-byte cap; stdout={at_cap_stdout}; stderr={at_cap_stderr}"
    );
    assert!(
        !at_cap_stderr.contains("strings-read cap"),
        "nothing was truncated, so nothing may be reported truncated; \
         stderr={at_cap_stderr}"
    );

    let over_cap = scan_binary_target(
        &target,
        None,
        &["--limit-binary-read-bytes", &format!("{}B", exact - 1)],
    );
    let over_stdout = stdout_of(&over_cap);
    let over_stderr = stderr_of(&over_cap);
    assert!(
        over_stderr.contains("strings-read cap")
            && over_stderr.contains("were not scanned")
            || over_stderr.contains("only the first"),
        "a truncated binary read must be SURFACED: the unread tail is a \
         coverage gap; stderr={over_stderr}"
    );
    assert!(
        over_stdout.contains(HEAD_KEY),
        "the prefix that WAS read must still report its finding; \
         stdout={over_stdout}"
    );

    let under_cap = scan_binary_target(
        &target,
        None,
        &["--limit-binary-read-bytes", &format!("{}B", exact + 1)],
    );
    let under_stdout = stdout_of(&under_cap);
    assert!(
        under_stdout.contains(HEAD_KEY) && under_stdout.contains(TAIL_KEY),
        "one byte of headroom behaves like the exact cap; stdout={under_stdout}"
    );
    assert!(
        !stderr_of(&under_cap).contains("strings-read cap"),
        "stderr={}",
        stderr_of(&under_cap)
    );
}

/// KH-202. Decompiler output is bounded by exact byte length, and exceeding
/// the bound degrades to shallow strings extraction with a loud warning.
/// Reporting the degraded run as a complete deep scan would be the failure.
#[test]
fn limit_binary_decompiled_bytes_bounds_decompiler_output_exactly() {
    let Some(fixture) = fake_ghidra_fixture() else {
        return;
    };

    let at_cap = scan_binary_target(
        &fixture.target,
        Some(&fixture.config_path),
        &[
            "--limit-binary-decompiled-bytes",
            &format!("{}B", fixture.output_bytes),
        ],
    );
    let at_cap_stdout = stdout_of(&at_cap);
    let at_cap_stderr = stderr_of(&at_cap);
    assert!(
        at_cap_stdout.contains(DECOMPILED_KEY),
        "decompiled output of exactly {} bytes must fit a {}-byte cap and its \
         findings must be reported; stdout={at_cap_stdout}; stderr={at_cap_stderr}",
        fixture.output_bytes,
        fixture.output_bytes
    );
    assert!(
        !at_cap_stderr.contains("Ghidra decompiled output"),
        "nothing exceeded the cap, so no degradation may be reported; \
         stderr={at_cap_stderr}"
    );

    let over_cap = scan_binary_target(
        &fixture.target,
        Some(&fixture.config_path),
        &[
            "--limit-binary-decompiled-bytes",
            &format!("{}B", fixture.output_bytes - 1),
        ],
    );
    let over_stdout = stdout_of(&over_cap);
    let over_stderr = stderr_of(&over_cap);
    assert!(
        over_stderr.contains("Ghidra decompiled output")
            && over_stderr.contains(&format!("{} bytes", fixture.output_bytes))
            && over_stderr.contains("falling back to shallow strings-only extraction"),
        "one byte over the cap must name the actual size, the cap, and the \
         degradation; stderr={over_stderr}"
    );
    assert!(
        !over_stdout.contains(DECOMPILED_KEY),
        "the decompiled output was refused, so its findings must NOT appear; \
         reporting them would mean the cap did not hold; stdout={over_stdout}"
    );
    assert!(
        over_stdout.contains(HEAD_KEY),
        "the strings fallback still covers the binary's own bytes; \
         stdout={over_stdout}"
    );
}

struct FakeGhidraFixture {
    _dir: TempDir,
    config_path: PathBuf,
    target: PathBuf,
    output_bytes: u64,
}

/// A fake `analyzeHeadless` that SUCCEEDS and writes decompiled output of an
/// exact size. The sibling `scan_binary_ghidra_stderr` fixture covers the
/// failing analyzer; this one is the only way to drive the output-size cap
/// without a real Ghidra install.
fn fake_ghidra_fixture() -> Option<FakeGhidraFixture> {
    if !cfg!(unix) {
        eprintln!("SKIP (loud): the fake analyzeHeadless fixture is a POSIX shell script");
        return None;
    }
    if default_system_analyze_headless_exists() {
        eprintln!(
            "SKIP (loud): a default trusted system analyzeHeadless exists ahead of \
             configured test dirs; keeping the system-first safe-bin contract"
        );
        return None;
    }

    let dir = TempDir::new().expect("tempdir");
    let bin_dir = dir.path().join("trusted-bin");
    std::fs::create_dir_all(&bin_dir).expect("create trusted-bin");
    let payload = format!("// FUNCTION: load_key\nchar *k = \"{DECOMPILED_KEY}\";\n");
    let output_bytes = payload.len() as u64;
    write_succeeding_fake_ghidra(&bin_dir, &payload);

    let config_path = dir.path().join(".keyhog.toml");
    let trusted_dir = bin_dir.to_string_lossy().replace('\\', "\\\\");
    std::fs::write(
        &config_path,
        format!("[system]\ntrusted_bin_dirs = [\"{trusted_dir}\"]\n"),
    )
    .expect("write config");

    let target = dir.path().join("fixture.bin");
    std::fs::write(
        &target,
        format!("\0\0AWS_ACCESS_KEY_ID = \"{HEAD_KEY}\"\0\0"),
    )
    .expect("write binary fixture");

    Some(FakeGhidraFixture {
        _dir: dir,
        config_path,
        target,
        output_bytes,
    })
}

#[cfg(unix)]
fn write_succeeding_fake_ghidra(bin_dir: &Path, payload: &str) {
    use std::os::unix::fs::PermissionsExt;

    // KeyHog invokes `analyzeHeadless <project> keyhog_analysis -import <bin>
    // -postScript <script> -deleteProject` and reads `decompiled.c` next to
    // the generated script, so the fake derives the output path the same way
    // instead of hardcoding a temp path it cannot know.
    let script = format!(
        "#!/bin/sh\nprev=\"\"\nscript=\"\"\nfor arg in \"$@\"; do\n  \
         if [ \"$prev\" = \"-postScript\" ]; then script=\"$arg\"; fi\n  \
         prev=\"$arg\"\ndone\n\
         [ -n \"$script\" ] || exit 3\n\
         printf '%s' '{payload}' > \"$(dirname \"$script\")/decompiled.c\"\nexit 0\n"
    );
    let path = bin_dir.join("analyzeHeadless");
    std::fs::write(&path, script).expect("write fake Ghidra");
    let mut permissions = std::fs::metadata(&path)
        .expect("fake Ghidra metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&path, permissions).expect("chmod fake Ghidra");
}

#[cfg(not(unix))]
fn write_succeeding_fake_ghidra(_bin_dir: &Path, _payload: &str) {}

#[cfg(unix)]
fn default_system_analyze_headless_exists() -> bool {
    [
        "/usr/bin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/sbin",
        "/bin",
        "/sbin",
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
    ]
    .iter()
    .any(|dir| Path::new(dir).join("analyzeHeadless").is_file())
}

#[cfg(not(unix))]
fn default_system_analyze_headless_exists() -> bool {
    true
}
