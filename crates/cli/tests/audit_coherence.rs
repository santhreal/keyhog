//! Adversarial audit: VECTOR 10 (COHERENCE).
//!
//! These are black-box CLI tests: they spawn the real `keyhog` binary and
//! assert that the numbers/labels it advertises to operators agree with the
//! numbers/labels the same binary actually emits, and with the documented
//! contract under `docs/`. Every assertion is drift-proof: it derives the
//! "expected" value from a live source of truth (the binary's own JSON output,
//! or the committed docs), never from a hardcoded constant, so the test stays
//! correct after the corpus grows or shrinks again.
//!
//! Each `#[test]` documents one finding: the drift, the file:line evidence,
//! and the expected fix.

use std::path::PathBuf;
use std::process::Command;

/// Resolve the keyhog binary under test.
///
/// `CARGO_BIN_EXE_keyhog` is injected by Cargo for integration tests and is the
/// canonical handle. We fall back to the prebuilt release-fast artifact if, for
/// some reason, the env handle points at a path that does not exist.
fn binary() -> PathBuf {
    let cargo_bin = PathBuf::from(env!("CARGO_BIN_EXE_keyhog"));
    if cargo_bin.exists() {
        return cargo_bin;
    }
    let prebuilt =
        PathBuf::from("/mnt/FlareTraining/santh-archive/cargo-target/release-fast/keyhog");
    if prebuilt.exists() {
        return prebuilt;
    }
    cargo_bin
}

fn run(args: &[&str]) -> (String, String, Option<i32>) {
    let out = Command::new(binary())
        .args(args)
        .output()
        .expect("spawn keyhog");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code(),
    )
}

/// Count top-level JSON objects in `keyhog detectors --format json` output without a
/// serde dependency: every detector object opens with the canonical first key
/// `"companions"` (the detectors subcommand serialises keys in a fixed order,
/// `companions` first). This is robust to the array growing/shrinking and to
/// pretty-printing, and avoids brittle brace-counting.
///
/// We cross-check against the array's structural shape: the output must start
/// with `[` and end with `]`.
fn embedded_detector_count(json: &str) -> usize {
    let trimmed = json.trim();
    assert!(
        trimmed.starts_with('[') && trimmed.ends_with(']'),
        "`detectors --format json` must emit a JSON array; got first 80 bytes: {:?}",
        &trimmed.chars().take(80).collect::<String>()
    );
    // Each detector object is rendered with `"companions"` as its first field.
    json.matches("\"companions\":").count()
}

/// AUD-coherence-1: `keyhog detectors --help` undercounts the embedded corpus.
///
/// FINDING: The detector count is 899 everywhere it is computed at runtime:
///   - `detectors/*.toml` on disk: 899 files
///   - `keyhog detectors --format json` array length: 899
///   - `keyhog detectors` summary header: "Loaded 899 detectors"
///   - tests/docker/scenarios.sh:95 expects "Loaded 899 detectors"
///   - README.md:19/50/60/80 say "899 detectors"
/// BUT the `--search` help text hardcodes a stale "894-strong corpus":
///   - crates/cli/src/args.rs:372  (`/// ... finding detectors in the 894-strong corpus`)
///   - crates/cli/src/subcommands/detectors.rs:45 (comment "The 894-strong corpus")
///   - crates/cli/src/orchestrator/mod.rs:188 (comment "all 894 regexes")
/// So an operator reading `keyhog detectors --help` is told there are 894
/// detectors while the same binary loads and lists 899.
///
/// This test is DRIFT-PROOF: it parses the number cited in `--help`
/// (`<N>-strong`) and asserts it EQUALS the live `--json` array length. It
/// fails today (894 != 899) and will pass once the help string is made dynamic
/// (or the constant is corrected) so the cited count tracks the real corpus.
///
/// EXPECTED FIX: replace the hardcoded "894-strong" literal in args.rs:372 with
/// the actual embedded detector count (e.g. injected at build time or rendered
/// at runtime), and update the stale comments. The existing tests
/// crates/cli/tests/gap/detectors_search_help_detector_count_drift.rs and
/// crates/cli/tests/stress/detectors_help_detector_count_drift.rs hardcode
/// "894-strong" and must also become dynamic (assert help count == actual
/// count) (but those are NOT edited here).
#[test]
fn detectors_help_count_matches_embedded_json_count() {
    let (help, _e, _c) = run(&["detectors", "--help"]);

    // Pull "<N>-strong" out of the help text.
    let cited = help
        .split("-strong")
        .next()
        .and_then(|prefix| {
            let digits: String = prefix
                .chars()
                .rev()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            let digits: String = digits.chars().rev().collect();
            digits.parse::<usize>().ok()
        })
        .unwrap_or_else(|| {
            panic!("could not find a `<N>-strong` corpus count in detectors --help:\n{help}")
        });

    let (json, _e2, _c2) = run(&["detectors", "--format", "json"]);
    let actual = embedded_detector_count(&json);

    assert_eq!(
        cited, actual,
        "detectors --help cites a {cited}-strong corpus, but the binary actually \
         loads and lists {actual} detectors (`detectors --format json` length). The help \
         text is stale; make it track the real count. Evidence: \
         crates/cli/src/args.rs:372."
    );
}

/// AUD-coherence-2: `--help` EXIT CODES omits a documented exit-4 producer.
///
/// FINDING: The committed exit-code contract in
/// docs/src/reference/exit-codes.md defines exit `4` as a *Health/self-test
/// failure* covering THREE producers:
///   "`keyhog doctor` unhealthy, `keyhog repair` could not restore a working
///    binary, `keyhog backend` self-test failed."
/// The source agrees through `crates/cli/src/exit_codes.rs`: exit 4 has multiple
/// producers (doctor, repair, backend self-test). The help text must not
/// describe it as backend-only.
/// An operator who reads `keyhog --help` is given an incomplete exit-4 contract
/// that does not match the documentation they are pointed at (README.md:83).
///
/// This test is drift-proof against the docs: it reads the live `--help` exit-4
/// line and asserts it acknowledges the `repair` producer that
/// docs/src/reference/exit-codes.md documents. It fails today (the help line
/// mentions only `backend`/self-test) and passes once the help text is widened
/// to match the documented contract.
///
/// EXPECTED FIX: keep the exit-4 line in `exit_codes::HELP` aligned with the
/// full exit-4 contract (doctor / repair / backend self-test), matching
/// docs/src/reference/exit-codes.md.
#[test]
fn help_exit_codes_describe_full_exit4_contract() {
    let (help, _e, _c) = run(&["--help"]);

    // Isolate the line documenting exit code 4 in the EXIT CODES block.
    let exit4_line = help
        .lines()
        .find(|l| l.trim_start().starts_with("4 ") || l.trim_start().starts_with("4\t"))
        .unwrap_or_else(|| {
            // Fall back: any line whose first token is "4".
            help.lines()
                .find(|l| {
                    l.trim_start()
                        .split_whitespace()
                        .next()
                        .map(|t| t == "4")
                        .unwrap_or(false)
                })
                .unwrap_or_else(|| panic!("no exit-code-4 line found in --help:\n{help}"))
        })
        .to_lowercase();

    // The committed contract (docs/src/reference/exit-codes.md) lists `repair`
    // as an exit-4 producer alongside backend self-test. The help text must not
    // present exit 4 as backend-only.
    assert!(
        exit4_line.contains("repair"),
        "`keyhog --help` exit-code 4 line ({exit4_line:?}) omits the `keyhog repair` \
         producer that docs/src/reference/exit-codes.md documents and that \
         crates/cli/src/exit_codes.rs (EXIT_REPAIR_FAILED = 4) emits. \
         The help exit-code contract drifted from the documented contract."
    );
}

/// AUD-coherence-3: `--help` calls exit 2 "Runtime error"; docs call it "user error".
///
/// FINDING: The same exit code 2 is labelled two contradictory ways:
///   - `keyhog --help`:
///       "2   Runtime error (e.g., config error, unreadable path)"
///   - docs/src/reference/exit-codes.md:
///       "`2`  User error: unknown CLI flag, `.keyhog.toml` parse failure, bad `--baseline`."
///   - docs/src/first-scan.md:
///       "`2`  User error - bad config, bad path, unsupported flag"
/// The binary's behaviour matches the DOCS' framing: an unknown flag exits 2
/// and a nonexistent path exits 2, both are *user* errors, distinct from the
/// "System error" reserved for exit 3. Calling exit 2 a "Runtime error" in
/// `--help` while the docs and `exit_codes.rs` (`EXIT_USER_ERROR: u8 = 2`) call it a
/// user error is a label disagreement on the same code: the two sources of
/// truth an operator consults give different names for the same exit.
///
/// This test verifies the behaviour (unknown flag -> 2) AND that the `--help`
/// label for exit 2 agrees with the documented "user error" wording. It fails
/// today because `--help` says "Runtime error", not "user error".
///
/// EXPECTED FIX: relabel the exit-2 line in `exit_codes::HELP` to "User error"
/// to match docs/src/reference/exit-codes.md, docs/src/first-scan.md, and the
/// `EXIT_USER_ERROR` constant name in crates/cli/src/exit_codes.rs.
#[test]
fn help_exit_code_2_label_matches_docs_user_error() {
    // Behavioural anchor: an unknown flag is a user error and must exit 2.
    let (_o, _e, code) = run(&["scan", "--this-flag-does-not-exist", "/tmp"]);
    assert_eq!(
        code,
        Some(2),
        "unknown CLI flag must exit 2 (EXIT_USER_ERROR); got {code:?}"
    );

    let (help, _e2, _c2) = run(&["--help"]);
    let exit2_line = help
        .lines()
        .find(|l| {
            l.trim_start()
                .split_whitespace()
                .next()
                .map(|t| t == "2")
                .unwrap_or(false)
        })
        .unwrap_or_else(|| panic!("no exit-code-2 line found in --help:\n{help}"))
        .to_lowercase();

    assert!(
        exit2_line.contains("user error"),
        "`keyhog --help` labels exit 2 as {exit2_line:?}, but docs/src/reference/\
         exit-codes.md and docs/src/first-scan.md call exit 2 a \"user error\" \
         (and crates/cli/src/exit_codes.rs names the constant EXIT_USER_ERROR). The \
         --help label drifted from the documented contract."
    );
}
