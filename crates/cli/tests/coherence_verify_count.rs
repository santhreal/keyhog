//! close-coherence: VERIFY-BLOCK COUNT doc↔corpus coherence.
//!
//! Docs intentionally avoid copied detector counts. This gate proves every
//! shipped `[detector.verify]` block has a URL and rejects stale numeric claims
//! on the user-facing surfaces.

use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

/// The keyhog binary under test (injected by Cargo for integration tests).
fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Run `keyhog scan <extra...> <clean-file>` offline and return the exit code.
fn scan_clean(extra: &[&str]) -> Option<i32> {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("clean.txt");
    std::fs::write(&path, "clean prose, no secrets here\n").unwrap();
    // Pin an explicit backend: a default `scan` resolves the backend from the
    // persisted autoroute cache and FAILS CLOSED (exit 2) when no decision exists
    // (Law 10, it never guesses). This test only checks that the --verify-rate /
    // --verify-batch flags parse and exit 0 on a clean file; it must not depend on
    // an ambient ~/.cache/keyhog/autoroute.json that exists on a dev box but never
    // on a fresh CI runner. `--backend cpu` bypasses autoroute deterministically.
    let mut args: Vec<&str> = vec!["scan", "--daemon=off", "--backend", "cpu"];
    args.extend_from_slice(extra);
    let p = path.to_string_lossy().into_owned();
    args.push(&p);
    let out = Command::new(binary())
        .args(&args)
        .output()
        .expect("spawn keyhog");
    let code = out.status.code();
    if code != Some(0) {
        eprintln!("Command failed: keyhog scan {extra:?}");
        eprintln!("STDOUT:\n{}", String::from_utf8_lossy(&out.stdout));
        eprintln!("STDERR:\n{}", String::from_utf8_lossy(&out.stderr));
    }
    code
}

/// Repo root: `crates/cli/../..`.
fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

/// Count detector TOMLs whose body contains a top-level `[detector.verify]`
/// header, and the subset of those whose verify block carries a `url` line.
/// Returns `(total_detectors, with_verify_header, with_verify_url)`.
fn count_verify_corpus(detectors: &Path) -> (usize, usize, usize) {
    let mut total = 0usize;
    let mut with_verify = 0usize;
    let mut with_verify_url = 0usize;
    let mut entries: Vec<PathBuf> = std::fs::read_dir(detectors)
        .expect("detectors/ dir readable")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    entries.sort();
    for path in entries {
        total += 1;
        let src = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read detector {}: {e}", path.display()));
        // Find the `[detector.verify]` section and check the lines that follow
        // (until the next `[` section header) for a `url` key.
        let mut in_verify = false;
        let mut has_header = false;
        let mut has_url = false;
        for line in src.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix('[') {
                // A new section header.
                let header = rest.trim_end_matches(']').trim();
                in_verify = header == "detector.verify";
                if in_verify {
                    has_header = true;
                }
                continue;
            }
            if in_verify {
                let key = t.split('=').next().map(str::trim).unwrap_or("");
                if key == "url" {
                    has_url = true;
                }
            }
        }
        if has_header {
            with_verify += 1;
        }
        if has_header && has_url {
            with_verify_url += 1;
        }
    }
    (total, with_verify, with_verify_url)
}

/// The corpus is the source of truth: every detector advertising a verify block
/// must carry a URL (otherwise the count is dishonest, a block with no URL is
/// `unverifiable`, not a live endpoint).
#[test]
fn every_verify_block_has_a_url() {
    let root = repo_root();
    let (_total, with_verify, with_verify_url) = count_verify_corpus(&root.join("detectors"));

    assert_eq!(
        with_verify_url, with_verify,
        "every `[detector.verify]` block must carry a `url` line, a verify block without a \
         URL is `unverifiable`, not a live endpoint, so counting it as one is dishonest. \
         {} of {with_verify} verify blocks have a url.",
        with_verify_url
    );
}

/// User docs must derive corpus counts from the installed binary, not copy them.
#[test]
fn user_docs_do_not_pin_detector_counts() {
    let root = repo_root();
    let readme = std::fs::read_to_string(root.join("README.md")).expect("README.md");
    let doc =
        std::fs::read_to_string(root.join("docs/src/verification.md")).expect("verification.md");
    assert!(
        !readme.contains("detectors carry an active `[detector.verify]` endpoint")
            && doc.contains("keyhog detectors --format json"),
        "docs must query the installed corpus instead of copying a detector count"
    );
}

/// verification.md's "Rate limits" section must quote the REAL default verify
/// rate. The verifier's process-wide limiter defaults to 5 rps (a 200 ms gap),
/// and the `--verify-rate` flag's clap default is `5.0`. A prior doc said
/// "100 ms gap" (which would be 10 rps), wrong. This pins the corrected prose so
/// it can't drift back: the doc must say "5 requests/second" and "200 ms", and
/// must NOT carry the stale "100 ms gap".
#[test]
fn verification_doc_rate_limit_matches_default_rps() {
    let root = repo_root();
    let doc =
        std::fs::read_to_string(root.join("docs/src/verification.md")).expect("verification.md");
    assert!(
        doc.contains("5 requests/second"),
        "verification.md Rate-limits section must state the real default of 5 requests/second \
         (the verifier limiter and `--verify-rate` default are both 5.0 rps)."
    );
    assert!(
        doc.contains("200 ms"),
        "verification.md must state the real 200 ms inter-call gap (1s / 5 rps = 200 ms), \
         not the stale 100 ms."
    );
    assert!(
        !doc.contains("100 ms gap"),
        "verification.md still carries the stale \"100 ms gap\" claim; 5 rps is a 200 ms gap."
    );
    // The doc must mention the two flags that tune this, they are real `scan`
    // flags, so documenting them closes the wiring gap.
    for flag in ["--verify-rate", "--verify-batch"] {
        assert!(
            doc.contains(flag),
            "verification.md Rate-limits section must mention the real `{flag}` flag that \
             controls verification rate limiting."
        );
    }
}

/// The `--verify-rate <RPS>` and `--verify-batch` flags verification.md now
/// advertises must be REAL `scan` flags: passing each on a clean file exits 0,
/// never exit 2 (clap unknown-flag). Drives the real binary so a doc claim about
/// a flag can never outrun the flag's existence.
#[test]
fn verify_rate_and_batch_flags_are_accepted() {
    // `--verify-batch` requires `--verify`; on a clean file there is nothing to
    // verify, so the scan stays offline and exits 0.
    for extra in [
        vec!["--verify-rate", "2.5", "--verify"],
        vec!["--verify-batch", "--verify"],
    ] {
        let code = scan_clean(&extra);
        assert_eq!(
            code,
            Some(0),
            "`keyhog scan {extra:?}` on a clean file must exit 0 (the flag is a real, \
             documented `scan` flag in docs/src/verification.md); got {code:?}"
        );
    }
}
