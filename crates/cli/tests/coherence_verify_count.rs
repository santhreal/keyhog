//! close-coherence — VERIFY-BLOCK COUNT doc↔corpus coherence.
//!
//! README.md and docs/src/verification.md make a NUMERIC claim about how many
//! shipped detectors carry a live `[detector.verify]` endpoint:
//!   * README:        "344 detectors carry an active `[detector.verify]` endpoint"
//!   * verification.md "344 of the 909 detectors do (about 38%)"
//!
//! A prior README said 341 and verification.md said "About 60%"; both had drifted
//! from the corpus (the real count is 344 of 909 = 38%). A doc number nobody pins
//! to the artifact rots silently — the operator reading "60%" mis-plans which
//! findings `--verify` can confirm.
//!
//! This test is the SOURCE OF TRUTH guard: it counts the real `[detector.verify]`
//! headers in the shipped `detectors/*.toml` corpus and asserts BOTH docs quote
//! that exact count. It also asserts every verify block has a `url` line (so the
//! count is honest: a verify block without a URL is `unverifiable`, not a live
//! endpoint). If a detector with/without a verify endpoint is added or removed,
//! this goes red until the docs are updated to the new count.

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
    // (Law 10 — it never guesses). This test only checks that the --verify-rate /
    // --verify-batch flags parse and exit 0 on a clean file; it must not depend on
    // an ambient ~/.cache/keyhog/autoroute.json that exists on a dev box but never
    // on a fresh CI runner. `--backend cpu` bypasses autoroute deterministically.
    let mut args: Vec<&str> = vec!["scan", "--no-daemon", "--backend", "cpu"];
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
/// must carry a URL (otherwise the count is dishonest — a block with no URL is
/// `unverifiable`, not a live endpoint). Pins the exact shipped counts so a
/// detector add/remove that changes them forces a doc update.
#[test]
fn verify_block_count_is_pinned_and_every_block_has_a_url() {
    let root = repo_root();
    let (total, with_verify, with_verify_url) = count_verify_corpus(&root.join("detectors"));

    assert_eq!(
        total, 909,
        "shipped detector corpus is 909 TOMLs (the README/docs cited total); got {total}. \
         If a detector was added/removed, update the README banner, verification.md, and \
         this assertion together."
    );
    assert_eq!(
        with_verify, 344,
        "exactly 344 detectors must carry a `[detector.verify]` header (the count README + \
         verification.md quote); got {with_verify}. Update both docs and this assertion in \
         lockstep when the count changes."
    );
    assert_eq!(
        with_verify_url, with_verify,
        "every `[detector.verify]` block must carry a `url` line — a verify block without a \
         URL is `unverifiable`, not a live endpoint, so counting it as one is dishonest. \
         {} of {with_verify} verify blocks have a url.",
        with_verify_url
    );
}

/// README's verifier-crate line must quote the corpus's real verify-block count.
/// Reads the committed README and the live corpus; if either drifts, red.
#[test]
fn readme_verifier_line_quotes_real_verify_count() {
    let root = repo_root();
    let (_total, with_verify, _url) = count_verify_corpus(&root.join("detectors"));
    let readme = std::fs::read_to_string(root.join("README.md")).expect("README.md");

    let needle = format!("{with_verify} detectors carry an active `[detector.verify]` endpoint");
    assert!(
        readme.contains(&needle),
        "README's verifier-crate line must quote the real verify-block count ({with_verify}); \
         expected substring {needle:?}. The corpus changed but the README number did not."
    );
}

/// verification.md's "Detectors without verification" section must quote the real
/// verify-block count AND the real total (`344 of the 902`), and must NOT keep the
/// stale "About 60%" claim (the true fraction is ~38%). Pins doc↔corpus agreement.
#[test]
fn verification_doc_quotes_real_verify_fraction() {
    let root = repo_root();
    let (total, with_verify, _url) = count_verify_corpus(&root.join("detectors"));
    let doc =
        std::fs::read_to_string(root.join("docs/src/verification.md")).expect("verification.md");

    let needle = format!("{with_verify} of the {total} detectors do");
    assert!(
        doc.contains(&needle),
        "verification.md must state the real verify count and total; expected substring \
         {needle:?}. Corpus is {with_verify}/{total}."
    );
    assert!(
        !doc.contains("About 60%"),
        "verification.md still carries the stale \"About 60%\" claim; the real fraction is \
         {with_verify}/{total} (~{:.0}%).",
        (with_verify as f64 / total as f64) * 100.0
    );
}

/// verification.md's "Rate limits" section must quote the REAL default verify
/// rate. The verifier's process-wide limiter defaults to 5 rps (a 200 ms gap),
/// and the `--verify-rate` flag's clap default is `5.0`. A prior doc said
/// "100 ms gap" (which would be 10 rps) — wrong. This pins the corrected prose so
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
    // The doc must mention the two flags that tune this — they are real `scan`
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
