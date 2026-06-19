//! Adversarial capability audit (VECTOR 3 — CAPABILITY): archive / compressed
//! input handling. Every "cannot scan X" is a recall gap: a secret committed
//! inside that container is invisible to keyhog, and an attacker who knows the
//! blind spot simply ships the credential in that format.
//!
//! All three tests below are BLACK-BOX: they spawn the real `keyhog` binary
//! (`CARGO_BIN_EXE_keyhog`), feed it a container holding ONE unambiguous
//! `-----BEGIN OPENSSH PRIVATE KEY-----` block, and assert keyhog reports the
//! finding. The same private-key block scanned as a plain file IS detected
//! (detector `github-app-private-key`/`ssh-private-key`), and the same block
//! inside a `.zip` IS detected — both are asserted here as positive controls,
//! so a control failure cannot be confused with the documented gap.
//!
//! Each test writes its own fixtures into a TempDir and builds the container by
//! shelling out to the universally-present `tar` / `gzip` / `zip` tools. If a
//! tool is missing the test panics with a distinct message (an environment
//! problem, NOT the defect under audit).
//!
//! ── Findings ────────────────────────────────────────────────────────────────
//!
//! AUD-capability-1  `.tar` archives are skipped entirely (recall hole).
//!   Evidence: crates/sources/src/filesystem/filter.rs:35 lists "tar" (and :40
//!   "tgz") in SKIP_EXTENSIONS, and the per-file read gate in
//!   crates/sources/src/filesystem/extract.rs returns BEFORE the archive-unpack
//!   branch for any skipped extension. The archive branch
//!   (extract.rs:118 `if ext == "zip" || "apk" || "ipa" || "crx" || "jar"`)
//!   handles zip-family containers via `openpack`, so `.zip` content IS scanned
//!   — but there is no `tar` unpack branch at all. The comment at
//!   filter.rs:51-54 even acknowledges it: "The tar/7z/rar extensions stay
//!   skipped: no unpack branch handles them." `.tar` is the dominant Linux
//!   archive (docker layer exports, helm charts, source tarballs), so this is a
//!   first-class blind spot, not an edge case.
//!   Expected fix: add a `tar` unpack branch in extract.rs (mirroring the zip
//!   branch, e.g. via the `tar` crate already vendored for docker.rs) and drop
//!   "tar" from SKIP_EXTENSIONS, with the same per-entry size + zip-bomb caps.
//!
//! AUD-capability-2  `.tgz` / `.tar.gz` archives are skipped / not unpacked.
//!   Evidence: `.tgz` is in SKIP_EXTENSIONS (filter.rs:40) so it never reaches
//!   any decoder. A `.tar.gz` (extension `gz`) is NOT skipped — it routes to
//!   `extract_compressed_chunks` (extract.rs:195) which only gunzips the outer
//!   stream and feeds the raw tar bytes (512-byte tar headers interleaved with
//!   file content) straight to the scanner WITHOUT untarring, so per-file
//!   secrets are torn by the tar framing and the path metadata is wrong.
//!   Net effect: a `.tgz` holding a private key yields zero findings while the
//!   identical `.zip` yields one.
//!   Expected fix: detect a gzip(tar) (and bare `.tgz`) container and route it
//!   through the tar unpack branch instead of treating it as an opaque
//!   compressed byte stream.
//!
//! AUD-capability-3  plain `.gz`-compressed files yield zero findings.
//!   Evidence: `.gz` is intentionally NOT in SKIP_EXTENSIONS (filter.rs:36-39
//!   comment) and routes to `extract_compressed_chunks`
//!   (extract.rs:342) which calls `ziftsieve::extract_from_bytes(Gzip, ..)` and
//!   concatenates `block.literals()` per DEFLATE block. A single text file
//!   holding an OpenSSH private key, gzipped with stock `gzip`, is detected when
//!   uncompressed but produces ZERO findings once gzipped — the compressed
//!   extraction path runs but never surfaces the secret (literal-only block
//!   reassembly drops back-referenced bytes and/or the per-block `\n` splicing
//!   tears the credential). The capability is wired but does not actually work.
//!   Expected fix: make `extract_compressed_chunks` reconstruct the true
//!   decompressed bytes (full inflate, not literal runs) before scanning.

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// One unambiguous secret keyhog detects as a plain file (verified: detector
/// `github-app-private-key` / `ssh-private-key`, confidence 0.8). Multi-line
/// PEM block so it reads as a real key, not a placeholder.
const KEY_FIXTURE: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQy
NTUxOQAAACAabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01AAAAEAAA
AAAAAAAAtzc2gtZWQyNTUxOQAAACBabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQR
-----END OPENSSH PRIVATE KEY-----
";

/// Run `keyhog scan --path <path> --no-daemon --format json` and parse the
/// findings array. `--no-daemon` forces the full in-process pipeline so the
/// result does not depend on whether a daemon happens to be running on the
/// host. Returns the parsed JSON array of findings.
fn scan_json(path: &std::path::Path) -> Vec<serde_json::Value> {
    let out = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--backend",
            "simd",
            "--format",
            "json",
            "--path",
        ])
        .arg(path)
        .output()
        .expect("spawn keyhog scan");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let trimmed = stdout.trim();
    let val: serde_json::Value = serde_json::from_str(trimmed).unwrap_or_else(|e| {
        panic!(
            "keyhog scan stdout was not valid JSON ({e}).\nstdout: {trimmed}\nstderr: {}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    val.as_array()
        .unwrap_or_else(|| panic!("--format json must emit a JSON array, got: {trimmed}"))
        .clone()
}

/// True when at least one finding looks like the planted private key
/// (any detector whose id contains "private-key", which covers both
/// `github-app-private-key` and `ssh-private-key`).
fn has_private_key_finding(findings: &[serde_json::Value]) -> bool {
    findings.iter().any(|f| {
        f["detector_id"]
            .as_str()
            .map(|id| id.contains("private-key"))
            .unwrap_or(false)
    })
}

/// Build a positive control + a candidate container holding the same key.
/// Returns (control_findings_present, candidate_findings).
fn write_key_file(dir: &std::path::Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, KEY_FIXTURE).expect("write key fixture");
    p
}

fn require_tool(tool: &str) {
    let ok = Command::new(tool)
        .arg("--help")
        .output()
        .map(|o| o.status.success() || !o.stdout.is_empty() || !o.stderr.is_empty())
        .unwrap_or(false);
    assert!(
        ok,
        "test prerequisite `{tool}` is not available on PATH; this is an \
         environment problem, not the keyhog defect under audit"
    );
}

/// AUD-capability-1 — `.tar` content must be scanned, exactly as `.zip` is.
///
/// FAILS NOW: keyhog returns zero findings for a `.tar` holding a private key,
/// while the identical `.zip` returns the finding. PASSES once a tar unpack
/// branch is added (filter.rs drop "tar" + extract.rs tar branch).
#[test]
fn tar_archive_content_is_scanned_like_zip() {
    require_tool("tar");
    require_tool("zip");
    let dir = TempDir::new().expect("tempdir");

    let key = write_key_file(dir.path(), "leak.txt");

    // Positive control: plain file is detected (rules out a broken fixture).
    let control = scan_json(&key);
    assert!(
        has_private_key_finding(&control),
        "CONTROL FAILED: plain leak.txt should be detected as a private key; \
         got {control:#?}"
    );

    // Positive control: the SAME key inside a .zip IS detected today.
    let zip_path = dir.path().join("bundle.zip");
    let z = Command::new("zip")
        .arg("-qj")
        .arg(&zip_path)
        .arg(&key)
        .output()
        .expect("run zip");
    assert!(z.status.success(), "zip failed: {z:?}");
    let zip_findings = scan_json(&zip_path);
    assert!(
        has_private_key_finding(&zip_findings),
        "CONTROL FAILED: keyhog should detect the key inside a .zip; got {zip_findings:#?}"
    );

    // The actual capability under audit: the SAME key inside a .tar.
    let tar_path = dir.path().join("bundle.tar");
    let t = Command::new("tar")
        .arg("-cf")
        .arg(&tar_path)
        .arg("-C")
        .arg(dir.path())
        .arg("leak.txt")
        .output()
        .expect("run tar");
    assert!(t.status.success(), "tar failed: {t:?}");

    let tar_findings = scan_json(&tar_path);
    assert!(
        has_private_key_finding(&tar_findings),
        "CAPABILITY GAP (AUD-capability-1): keyhog scanned a .tar containing a \
         private key and reported NO private-key finding, even though the \
         identical .zip is detected. `.tar` is in SKIP_EXTENSIONS \
         (crates/sources/src/filesystem/filter.rs:35) and has no unpack branch \
         in crates/sources/src/filesystem/extract.rs. Findings: {tar_findings:#?}"
    );
}

/// AUD-capability-2 — `.tgz` / `.tar.gz` content must be scanned.
///
/// FAILS NOW: a gzip-compressed tar holding a private key yields zero findings
/// (the `.tgz` is skipped outright; a `.gz`-suffixed tarball is gunzipped but
/// never untarred). PASSES once gzip(tar) containers route through a tar
/// unpack branch.
#[test]
fn tgz_archive_content_is_scanned() {
    require_tool("tar");
    let dir = TempDir::new().expect("tempdir");

    let key = write_key_file(dir.path(), "leak.txt");

    // Positive control: plain file detected.
    assert!(
        has_private_key_finding(&scan_json(&key)),
        "CONTROL FAILED: plain leak.txt should be detected"
    );

    // .tar.gz (extension `gz`) — NOT in SKIP_EXTENSIONS, so the scanner
    // actually opens it via extract_compressed_chunks, gunzips, and scans the
    // raw (still-tarred) bytes. This is the most favourable case for the
    // current code and it STILL misses the secret.
    let targz_path = dir.path().join("bundle.tar.gz");
    let t = Command::new("tar")
        .arg("-czf")
        .arg(&targz_path)
        .arg("-C")
        .arg(dir.path())
        .arg("leak.txt")
        .output()
        .expect("run tar -czf");
    assert!(t.status.success(), "tar -czf failed: {t:?}");

    let findings = scan_json(&targz_path);
    assert!(
        has_private_key_finding(&findings),
        "CAPABILITY GAP (AUD-capability-2): keyhog scanned a .tar.gz containing \
         a private key and reported NO private-key finding. The gz path \
         (crates/sources/src/filesystem/extract.rs:195 -> extract_compressed_chunks) \
         gunzips but never untars, and bare .tgz is skipped via \
         crates/sources/src/filesystem/filter.rs:40. Findings: {findings:#?}"
    );
}

/// AUD-capability-3 — plain `.gz`-compressed files must be scanned.
///
/// FAILS NOW: a single text file holding an OpenSSH private key, gzipped with
/// stock `gzip`, yields zero findings — yet the uncompressed file yields one.
/// `extract_compressed_chunks` runs but its literal-block reassembly never
/// surfaces the secret. PASSES once compressed extraction reconstructs the true
/// decompressed bytes before scanning.
#[test]
fn plain_gzip_file_content_is_scanned() {
    require_tool("gzip");
    let dir = TempDir::new().expect("tempdir");

    let key = write_key_file(dir.path(), "leak.txt");

    // Positive control: plain file detected.
    assert!(
        has_private_key_finding(&scan_json(&key)),
        "CONTROL FAILED: plain leak.txt should be detected"
    );

    // gzip -> leak.txt.gz (single deflate stream, no tar involved).
    let gz_path = dir.path().join("leak.txt.gz");
    let raw = std::fs::read(&key).expect("read key");
    let g = Command::new("gzip")
        .arg("-c")
        .arg(&key)
        .output()
        .expect("run gzip -c");
    assert!(g.status.success(), "gzip failed: {g:?}");
    assert!(
        !g.stdout.is_empty() && g.stdout.len() != raw.len(),
        "gzip produced no/identical output: {} bytes",
        g.stdout.len()
    );
    std::fs::write(&gz_path, &g.stdout).expect("write .gz fixture");

    let findings = scan_json(&gz_path);
    assert!(
        has_private_key_finding(&findings),
        "CAPABILITY GAP (AUD-capability-3): keyhog scanned a .gz-compressed file \
         containing a private key and reported NO private-key finding, even \
         though the uncompressed file is detected. extract_compressed_chunks \
         (crates/sources/src/filesystem/extract.rs:342) runs but its \
         literal-block reassembly never reconstructs the credential. \
         Findings: {findings:#?}"
    );
}
