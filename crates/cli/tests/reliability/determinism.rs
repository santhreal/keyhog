//! Invariant: a command with no time/randomness in its output is byte-identical
//! across two runs under the same profile. Nondeterministic output (HashMap
//! iteration order, unstable sorts) breaks diffing, caching, and golden-file
//! review - a real "behaves inconsistently" defect even when nothing errors.
//!
//! 6 deterministic invocations × 16 profiles = 96 distinct tests.

use crate::reliability::harness::{assert_no_panic, run, Profile};

pub fn deterministic(profile: Profile, args: &[&str]) {
    let a = run(profile, args);
    let b = run(profile, args);
    assert_no_panic(&a);
    assert_no_panic(&b);
    assert_eq!(
        a.code, b.code,
        "{}: exit code differs between identical runs ({:?} vs {:?})",
        a.what, a.code, b.code
    );
    assert_eq!(
        a.stdout, b.stdout,
        "{}: stdout is NOT deterministic across two identical runs.\n--- run A (first 600) ---\n{}\n--- run B (first 600) ---\n{}",
        a.what,
        a.stdout.chars().take(600).collect::<String>(),
        b.stdout.chars().take(600).collect::<String>()
    );
}

crate::kh_matrix!(
    crate::reliability::determinism::deterministic,
    version => &["--version"][..],
    completion_bash => &["completion", "bash"][..],
    completion_zsh => &["completion", "zsh"][..],
    detectors_list => &["detectors"][..],
    scan_help => &["scan", "--help"][..],
    badflag => &["scan", "--definitely-not-a-real-keyhog-flag"][..],
);

fn planted_corpus() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let file1 = dir.path().join("aws_config.py");
    std::fs::write(
        &file1,
        b"# AWS Credentials configuration\naws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\naws_secret_access_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\nregion = \"us-east-1\"\n",
    )
    .expect("write file1");

    let file2 = dir.path().join("github_token.env");
    std::fs::write(
        &file2,
        b"export GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\nexport GITHUB_API_URL=https://api.github.com\n",
    )
    .expect("write file2");

    let file3 = dir.path().join("clean_code.rs");
    std::fs::write(
        &file3,
        b"fn main() {\n    println!(\"Hello, world!\");\n}\n",
    )
    .expect("write file3");

    dir
}

/// WHY: every output format produced by KeyHog must be byte-identical across identical runs
/// on the same input corpus, preventing unordered map iteration or non-deterministic serialization
/// from breaking golden testing, CI diffing, and caching.
///
/// The deliberate exceptions are per-scan metadata fields that are volatile BY
/// DESIGN — the scan id, wall-clock stamps, and measured duration. They are
/// normalized out before comparison; every other byte of every format must
/// match.
///
/// What it does not catch: interactive TTY-only ANSI escape sequences.
fn normalize_volatile_fields(stdout: &str) -> String {
    /// Blank the value of every `"KEY":<value>` occurrence, quoted or numeric.
    fn blank_field(s: &str, key: &str) -> String {
        let marker = format!("\"{key}\":");
        let mut out = String::with_capacity(s.len());
        let mut rest = s;
        while let Some(i) = rest.find(&marker) {
            let after = rest[i + marker.len()..].trim_start();
            let leading_ws = rest[i + marker.len()..].len() - after.len();
            if after.starts_with('"') {
                match after[1..].find('"') {
                    Some(end) => {
                        out.push_str(&rest[..i + marker.len() + leading_ws]);
                        out.push_str("\"<volatile>\"");
                        rest = &after[end + 2..];
                    }
                    None => break,
                }
            } else {
                let digits = after
                    .find(|c: char| !c.is_ascii_digit() && c != '.')
                    .unwrap_or(after.len());
                out.push_str(&rest[..i + marker.len() + leading_ws]);
                out.push_str("<n>");
                rest = &after[digits..];
            }
        }
        out.push_str(rest);
        out
    }
    let mut out = stdout.to_owned();
    for key in [
        "scan_id",
        "generated_at",
        "scan_started_at",
        "scan_finished_at",
        "created",
        "duration_ms",
        "written_at_ns",
    ] {
        out = blank_field(&out, key);
    }
    out
}

#[test]
fn deterministic_scan_formats_across_all_registered_reporters() {
    use clap::ValueEnum;
    use keyhog::args::OutputFormat;

    let corpus = planted_corpus();
    let corpus_path = corpus.path().to_str().expect("valid utf-8 path");

    // Dynamically derive the variant space from ALL registered OutputFormat variants
    for format in OutputFormat::value_variants() {
        let fmt_str = format.to_string();
        let args = ["scan", "--format", &fmt_str, corpus_path];

        let a = run(Profile::Plain, &args);
        let b = run(Profile::Plain, &args);

        assert_no_panic(&a);
        assert_no_panic(&b);
        assert_eq!(
            a.code, b.code,
            "format `{fmt_str}`: exit code differs across identical runs ({:?} vs {:?})",
            a.code, b.code
        );
        assert_eq!(
            normalize_volatile_fields(&a.stdout),
            normalize_volatile_fields(&b.stdout),
            "format `{fmt_str}`: stdout is NOT deterministic across identical runs over planted corpus.\n--- run A ---\n{}\n--- run B ---\n{}",
            a.stdout, b.stdout
        );
    }
}

/// WHY: baseline entries and incremental Merkle index serialization must be
/// byte-identical across repeated runs on the same input corpus. The baseline
/// header carries a `created` wall-clock stamp by design; it is normalized out
/// before comparison, and everything else must match.
///
/// What it does not catch: corrupt filesystems during baseline writes.
#[test]
fn deterministic_baseline_and_merkle_index() {
    let corpus = planted_corpus();
    let corpus_path = corpus.path().to_str().expect("valid utf-8 path");

    let temp_out = tempfile::tempdir().expect("tempdir");
    let baseline_a = temp_out.path().join("baseline_a.json");
    let baseline_b = temp_out.path().join("baseline_b.json");

    // `--create-baseline` WRITES a baseline; `--baseline` is the compare-and-
    // suppress flag and never writes.
    let args_base_a = [
        "scan",
        "--create-baseline",
        baseline_a.to_str().unwrap(),
        corpus_path,
    ];
    let args_base_b = [
        "scan",
        "--create-baseline",
        baseline_b.to_str().unwrap(),
        corpus_path,
    ];

    let run_a = run(Profile::Plain, &args_base_a);
    let run_b = run(Profile::Plain, &args_base_b);
    assert_no_panic(&run_a);
    assert_no_panic(&run_b);

    assert_eq!(
        normalize_volatile_fields(
            &String::from_utf8(std::fs::read(&baseline_a).expect("read baseline a"))
                .expect("baseline is UTF-8")
        ),
        normalize_volatile_fields(
            &String::from_utf8(std::fs::read(&baseline_b).expect("read baseline b"))
                .expect("baseline is UTF-8")
        ),
        "baseline files must be identical apart from the created stamp"
    );

    let merkle_a = temp_out.path().join("merkle_a.json");
    let merkle_b = temp_out.path().join("merkle_b.json");

    // `--incremental-cache` only overrides the index location; `--incremental`
    // is what turns the Merkle index on and makes the scan persist it.
    let args_merkle_a = [
        "scan",
        "--incremental",
        "--incremental-cache",
        merkle_a.to_str().unwrap(),
        corpus_path,
    ];
    let args_merkle_b = [
        "scan",
        "--incremental",
        "--incremental-cache",
        merkle_b.to_str().unwrap(),
        corpus_path,
    ];

    let run_m_a = run(Profile::Plain, &args_merkle_a);
    let run_m_b = run(Profile::Plain, &args_merkle_b);
    assert_no_panic(&run_m_a);
    assert_no_panic(&run_m_b);

    let normalize = |bytes: Vec<u8>| {
        normalize_volatile_fields(&String::from_utf8(bytes).expect("index is UTF-8"))
    };
    assert_eq!(
        normalize(std::fs::read(&merkle_a).expect("read merkle a")),
        normalize(std::fs::read(&merkle_b).expect("read merkle b")),
        "merkle index files must be identical apart from the write stamp"
    );
}
