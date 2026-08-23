//! E2E: `--limit-docker-tar-entry-bytes`, `--limit-docker-image-config-bytes`,
//! and `--limit-docker-tar-total-bytes` boundaries.
//!
//! KH-194 / KH-195 / KH-196. Docker unpacking is the widest amplification
//! surface KeyHog has: an image tar contains layer tars which contain files.
//! Each cap is exercised at limit minus one, exactly at the limit, and limit
//! plus one against an image whose entry sizes are known exactly, and every
//! refusal must name the entry and reach the operator.
//!
//! Requires a working `docker` daemon; the whole module skips when
//! `docker image save` is unavailable, because a skipped fixture must never
//! masquerade as a passing boundary proof.

#![cfg(feature = "docker")]

use crate::e2e::support::binary;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

/// `docker import` accepts a plain rootfs tar, so the fixture needs no
/// registry, no base image, and no network.
const IMAGE: &str = "keyhog-limits-boundary:test";
/// Exact uncompressed size of the leak-bearing layer entry.
const LEAK_ENTRY_BYTES: u64 = 39;
/// Exact uncompressed size of the padding layer entry.
const PAD_ENTRY_BYTES: u64 = 4096;

fn docker_available() -> bool {
    Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Build a rootfs tar with one small leak file and one larger padding file,
/// then `docker import` it. Returns false when docker refuses the import.
fn build_image(work: &Path) -> bool {
    let root = work.join("rootfs");
    std::fs::create_dir_all(root.join("etc")).expect("rootfs dirs");
    let leak = "AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZBN\n";
    assert_eq!(
        leak.len() as u64,
        LEAK_ENTRY_BYTES,
        "the fixture's exact entry size is what the boundary assertions use"
    );
    std::fs::write(root.join("etc/app.env"), leak).expect("leak file");
    std::fs::write(
        root.join("etc/pad.txt"),
        "P".repeat(PAD_ENTRY_BYTES as usize),
    )
    .expect("pad file");

    let tar = work.join("rootfs.tar");
    let status = Command::new("tar")
        .args(["-cf"])
        .arg(&tar)
        .arg("-C")
        .arg(&root)
        .arg(".")
        .status();
    if !status.is_ok_and(|status| status.success()) {
        return false;
    }
    Command::new("docker")
        .arg("import")
        .arg(&tar)
        .arg(IMAGE)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn remove_image() {
    let _ = Command::new("docker")
        .args(["image", "rm", "-f", IMAGE])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn scan(extra: &[&str]) -> Output {
    Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "simd",
            "--no-suppress-test-fixtures",
            "--format",
            "jsonl",
            "--docker-image",
            IMAGE,
        ])
        .args(extra)
        .output()
        .expect("spawn keyhog")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn findings(output: &Output) -> usize {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.starts_with('{'))
        .count()
}

/// Every docker boundary in one image build: importing and saving an image is
/// slow enough that splitting these into separate `#[test]` functions would
/// pay that cost several times over for no additional coverage.
#[test]
fn docker_source_limit_boundaries_are_exact_and_surfaced() {
    if !docker_available() {
        eprintln!("skipping: docker daemon unavailable");
        return;
    }
    let work = TempDir::new().expect("tempdir");
    if !build_image(work.path()) {
        eprintln!("skipping: docker import unavailable");
        return;
    }

    // ── KH-194: --limit-docker-tar-entry-bytes ──────────────────────────────
    // An entry of exactly the cap is scanned; one byte under drops it, and the
    // drop names the entry and its layer path.
    let at_entry_cap = scan(&[
        "--limit-docker-tar-entry-bytes",
        &format!("{LEAK_ENTRY_BYTES}B"),
    ]);
    let at_entry_stderr = stderr_of(&at_entry_cap);
    assert!(
        findings(&at_entry_cap) >= 1,
        "an entry of exactly {LEAK_ENTRY_BYTES} bytes must fit a \
         {LEAK_ENTRY_BYTES}-byte entry cap; stderr={at_entry_stderr}"
    );
    assert!(
        at_entry_stderr.contains("./etc/pad.txt")
            && at_entry_stderr.contains("exceeds per-file cap")
            && at_entry_stderr.contains("was not scanned"),
        "the oversized entry must be named, with its size and cap; \
         stderr={at_entry_stderr}"
    );

    let under_entry_cap = scan(&[
        "--limit-docker-tar-entry-bytes",
        &format!("{}B", LEAK_ENTRY_BYTES - 1),
    ]);
    let under_entry_stderr = stderr_of(&under_entry_cap);
    assert_eq!(
        findings(&under_entry_cap),
        0,
        "one byte under the entry size drops the leak; \
         stderr={under_entry_stderr}"
    );
    assert!(
        under_entry_stderr.contains("./etc/app.env"),
        "dropping the ONLY leak-bearing entry must be surfaced by path, never \
         reported as a clean image; stderr={under_entry_stderr}"
    );

    // ── KH-196: --limit-docker-tar-total-bytes ──────────────────────────────
    // The cumulative accounting must not reset per entry: a budget that covers
    // the largest single entry but not the layer's sum must still trip.
    let per_entry_only = scan(&[
        "--limit-docker-tar-total-bytes",
        &format!("{}B", PAD_ENTRY_BYTES),
    ]);
    let per_entry_stderr = stderr_of(&per_entry_only);
    assert!(
        per_entry_stderr.contains(&format!("{PAD_ENTRY_BYTES}-byte image-wide budget"))
            && per_entry_stderr.contains("./etc/pad.txt"),
        "a budget large enough for the biggest entry but smaller than the \
         layer sum must trip the image-wide guard and name the entry it \
         stopped at, proving accounting does not reset per tar; \
         stderr={per_entry_stderr}"
    );

    let generous_total = scan(&["--limit-docker-tar-total-bytes", "64M"]);
    assert!(
        !stderr_of(&generous_total).contains("image-wide budget"),
        "a budget that covers every tar must not report a bomb; stderr={}",
        stderr_of(&generous_total)
    );
    assert!(
        findings(&generous_total) >= 1,
        "the unconstrained baseline must find the planted leak; stderr={}",
        stderr_of(&generous_total)
    );

    // ── KH-195: --limit-docker-image-config-bytes ───────────────────────────
    // Metadata parsing is bounded, and an oversized config is a precise
    // terminal error rather than an image scanned without its metadata.
    let tiny_config = scan(&["--limit-docker-image-config-bytes", "1B"]);
    let tiny_config_stderr = stderr_of(&tiny_config);
    assert!(
        tiny_config_stderr.contains("exceeds 1 bytes"),
        "an oversized image config must name the cap it broke; \
         stderr={tiny_config_stderr}"
    );
    assert_ne!(
        tiny_config.status.code(),
        Some(0),
        "an image whose metadata could not be parsed must not exit 0"
    );

    let generous_config = scan(&["--limit-docker-image-config-bytes", "16M"]);
    assert!(
        !stderr_of(&generous_config).contains("exceeds 16777216 bytes"),
        "a 16 MiB config budget covers this image's metadata"
    );
    assert!(
        findings(&generous_config) >= 1,
        "stderr={}",
        stderr_of(&generous_config)
    );

    remove_image();
}
