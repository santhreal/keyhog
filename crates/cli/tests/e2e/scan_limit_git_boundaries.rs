//! E2E: `--limit-git-line-bytes`, `--limit-git-total-bytes`,
//! `--limit-git-blob-bytes`, and `--limit-git-chunks` boundaries.
//!
//! KH-197 / KH-198 / KH-199 / KH-200. Each flag is exercised at limit minus
//! one, exactly at the limit, and limit plus one against a fixture whose byte
//! and chunk counts are known exactly, and each over-limit run must SURFACE the
//! drop: a silently smaller scan is a false clean.

#![cfg(feature = "git")]

use crate::e2e::support::binary;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

/// A leak the default corpus reports, plus filler that pads its line to an
/// exact length. Repeating filler would risk a degenerate-run suppression, so
/// the pad cycles.
///
/// `tag` is the key's last character. Findings deduplicate by credential, so
/// fixtures that must each contribute a finding need distinct keys.
fn padded_leak(tag: char, total_len: usize) -> String {
    let mut line = format!("AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZB{tag}#");
    line.reserve(total_len.saturating_sub(line.len()));
    let filler = "abcdefghij";
    while line.len() < total_len {
        let want = total_len - line.len();
        line.push_str(&filler[..want.min(filler.len())]);
    }
    assert_eq!(line.len(), total_len, "fixture line length must be exact");
    line
}

fn git(repo: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(repo)
        .status()
        .unwrap_or_else(|error| panic!("git {args:?}: {error}"));
    assert!(status.success(), "git {args:?} failed");
}

fn init_repo(repo: &Path) {
    git(repo, &["init", "-q"]);
    git(repo, &["config", "user.email", "limits@test"]);
    git(repo, &["config", "user.name", "Limits Audit"]);
}

fn commit_file(repo: &Path, name: &str, body: &str) {
    std::fs::write(repo.join(name), body).expect("write fixture");
    git(repo, &["add", name]);
    git(repo, &["commit", "-q", "-m", name]);
}

fn scan(repo: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(binary());
    command
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "simd",
            "--no-suppress-test-fixtures",
        ])
        .args(args)
        .current_dir(repo);
    command.output().expect("spawn keyhog")
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

/// KH-197. The cap counts the LINE, not the line plus its terminator, so a
/// diff line whose content is exactly `cap` bytes is scanned. Charging the
/// newline rejected exactly-at-cap input one byte early and disagreed with
/// every other KeyHog byte cap.
#[test]
fn limit_git_line_bytes_admits_a_line_of_exactly_the_cap_and_surfaces_a_longer_one() {
    let dir = TempDir::new().expect("tempdir");
    let repo = dir.path();
    init_repo(repo);
    // 600 content bytes; `git log -p` prefixes added lines with `+`, so the
    // longest diff line carries 601 content bytes. Every other line git emits
    // for this repo (commit/Author/Date/diff --git/index/@@) is far shorter.
    let leak_line_bytes = 601;
    commit_file(repo, ".env.leak", &format!("{}\n", padded_leak('N', 600)));

    let at_cap = scan(
        repo,
        &[
            "--git-history",
            ".",
            "--limit-git-line-bytes",
            &format!("{leak_line_bytes}B"),
            "--format",
            "jsonl",
        ],
    );
    let at_cap_stderr = stderr_of(&at_cap);
    assert!(
        !at_cap_stderr.contains("line cap"),
        "a diff line of exactly {leak_line_bytes} content bytes must fit \
         --limit-git-line-bytes {leak_line_bytes}B; stderr={at_cap_stderr}"
    );
    assert!(
        findings(&at_cap) >= 1,
        "the exactly-at-cap line carries the leak and must still be reported; \
         stderr={at_cap_stderr}"
    );

    let over_cap = scan(
        repo,
        &[
            "--git-history",
            ".",
            "--limit-git-line-bytes",
            &format!("{}B", leak_line_bytes - 1),
            "--format",
            "jsonl",
        ],
    );
    let over_cap_stderr = stderr_of(&over_cap);
    assert!(
        over_cap_stderr.contains("line cap") && over_cap_stderr.contains("was not scanned"),
        "one byte over the cap must SURFACE the dropped line, never drop it \
         silently; stderr={over_cap_stderr}"
    );
    assert_eq!(
        findings(&over_cap),
        0,
        "the dropped line was the only leak, so the run must report nothing \
         AND say so; stderr={over_cap_stderr}"
    );

    let under_cap = scan(
        repo,
        &[
            "--git-history",
            ".",
            "--limit-git-line-bytes",
            &format!("{}B", leak_line_bytes + 1),
            "--format",
            "jsonl",
        ],
    );
    assert!(
        !stderr_of(&under_cap).contains("line cap"),
        "one byte of headroom must behave like the exact cap"
    );
}

/// KH-199. `--git-blobs` enumerates blob objects, so the cap applies to the
/// blob's exact byte length. Reachable blobs at, below, and above the bound
/// must be included / included / skipped-and-surfaced.
#[test]
fn limit_git_blob_bytes_includes_an_exactly_sized_blob_and_surfaces_a_larger_one() {
    let dir = TempDir::new().expect("tempdir");
    let repo = dir.path();
    init_repo(repo);
    let leak = format!("{}\n", padded_leak('N', 120));
    let leak_bytes = leak.len();
    commit_file(repo, ".env.small", &leak);
    // A second, strictly larger blob so a cap set to the small blob's exact
    // size proves inclusion of one and exclusion of the other in one run.
    commit_file(repo, "large.env", &format!("{}\n", padded_leak('P', 400)));

    let at_cap = scan(
        repo,
        &[
            "--git-blobs",
            ".",
            "--limit-git-blob-bytes",
            &format!("{leak_bytes}B"),
            "--format",
            "jsonl",
        ],
    );
    let at_cap_stderr = stderr_of(&at_cap);
    assert!(
        findings(&at_cap) >= 1,
        "a blob of exactly {leak_bytes} bytes must fit a {leak_bytes}-byte cap; \
         stderr={at_cap_stderr}"
    );
    assert!(
        at_cap_stderr.contains("per-blob size cap") && at_cap_stderr.contains("was not scanned"),
        "the larger blob was skipped and that is a coverage gap the operator \
         must see; stderr={at_cap_stderr}"
    );

    let over_cap = scan(
        repo,
        &[
            "--git-blobs",
            ".",
            "--limit-git-blob-bytes",
            &format!("{}B", leak_bytes - 1),
            "--format",
            "jsonl",
        ],
    );
    let over_cap_stderr = stderr_of(&over_cap);
    assert_eq!(
        findings(&over_cap),
        0,
        "one byte under the blob size drops it; stderr={over_cap_stderr}"
    );
    assert!(
        over_cap_stderr.contains("per-blob size cap"),
        "dropping every blob must not produce a quiet clean; \
         stderr={over_cap_stderr}"
    );
    assert_ne!(
        over_cap.status.code(),
        Some(0),
        "a run that scanned no requested input must not exit 0"
    );
}

/// KH-198. The aggregate byte budget stops history enumeration, and the cutoff
/// is reported as a coverage gap with the exact byte count and cap.
#[test]
fn limit_git_total_bytes_cuts_history_and_reports_the_exact_cutoff() {
    let dir = TempDir::new().expect("tempdir");
    let repo = dir.path();
    init_repo(repo);
    commit_file(repo, "one.env", &format!("{}\n", padded_leak('N', 120)));
    commit_file(repo, "two.env", &format!("{}\n", padded_leak('P', 120)));
    commit_file(repo, "three.env", &format!("{}\n", padded_leak('R', 120)));

    let generous = scan(
        repo,
        &[
            "--git-history",
            ".",
            "--limit-git-total-bytes",
            "1M",
            "--format",
            "jsonl",
        ],
    );
    let all = findings(&generous);
    assert!(
        all >= 2,
        "fixture must produce several history findings to bound; \
         stderr={}",
        stderr_of(&generous)
    );
    assert!(
        !stderr_of(&generous).contains("aggregate byte cap"),
        "a budget the history never reaches must not report a cap"
    );

    let tight = scan(
        repo,
        &[
            "--git-history",
            ".",
            "--limit-git-total-bytes",
            "1B",
            "--format",
            "jsonl",
        ],
    );
    let tight_stderr = stderr_of(&tight);
    assert!(
        tight_stderr.contains("aggregate byte cap reached")
            && tight_stderr.contains("were not scanned"),
        "an exhausted byte budget truncates the scan and must say so; \
         stderr={tight_stderr}"
    );
    assert!(
        findings(&tight) < all,
        "the byte budget must actually cut work: {} of {all} findings survived",
        findings(&tight)
    );
}

/// KH-200. Zero, one, exactly-enough, and over-budget chunk counts. A cap
/// equal to the chunk count must NOT invent a coverage gap; anything smaller
/// must report one.
#[test]
fn limit_git_chunks_cuts_deterministically_and_only_reports_a_real_gap() {
    let dir = TempDir::new().expect("tempdir");
    let repo = dir.path();
    init_repo(repo);
    commit_file(repo, "one.env", &format!("{}\n", padded_leak('N', 120)));
    commit_file(repo, "two.env", &format!("{}\n", padded_leak('P', 120)));
    commit_file(repo, "three.env", &format!("{}\n", padded_leak('R', 120)));

    // Three single-hunk commits produce three history chunks.
    let exact = scan(
        repo,
        &[
            "--git-history",
            ".",
            "--limit-git-chunks",
            "3",
            "--format",
            "jsonl",
        ],
    );
    let exact_stderr = stderr_of(&exact);
    assert!(
        !exact_stderr.contains("chunk cap reached"),
        "a chunk cap that exactly covers the history scanned everything, so \
         reporting a gap would be crying wolf; stderr={exact_stderr}"
    );
    let all = findings(&exact);
    assert!(
        all >= 2,
        "fixture must yield several chunks worth of findings"
    );

    let one = scan(
        repo,
        &[
            "--git-history",
            ".",
            "--limit-git-chunks",
            "1",
            "--format",
            "jsonl",
        ],
    );
    let one_stderr = stderr_of(&one);
    assert!(
        one_stderr.contains("chunk cap reached") && one_stderr.contains("were not scanned"),
        "a one-chunk budget leaves history unscanned and must surface it; \
         stderr={one_stderr}"
    );
    assert!(
        findings(&one) < all,
        "a one-chunk budget must scan strictly less than the full history"
    );

    // Zero is refused at parse time rather than silently scanning nothing:
    // a budget of zero can only ever produce a false clean.
    let zero = scan(
        repo,
        &[
            "--git-history",
            ".",
            "--limit-git-chunks",
            "0",
            "--format",
            "jsonl",
        ],
    );
    assert_ne!(
        zero.status.code(),
        Some(0),
        "--limit-git-chunks 0 must fail closed, not scan zero chunks quietly; \
         stderr={}",
        stderr_of(&zero)
    );
}
