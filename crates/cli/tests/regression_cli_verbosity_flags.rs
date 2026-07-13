//! Regression contract for the CLI's color / verbosity surface: `NO_COLOR`,
//! `detectors --verbose`, and the `--quiet` documentation surface.
//!
//! Every assertion pins a CONCRETE value, driving the REAL shipped binary
//! (`env!("CARGO_BIN_EXE_keyhog")`) as a child process with a *captured* (piped,
//! non-TTY) stdout/stderr (exactly the shape a script or CI redirect sees).
//!
//! HOST-INDEPENDENCE: none of these assertions depend on Hyperscan/SIMD/GPU.
//! They exercise the `detectors` listing, `--version`, and `--help` surfaces,
//! which are pure metadata paths with no accelerator dependency. The color
//! contract itself is host-independent by construction: `style::for_stdout`
//! resolves to the PLAIN palette whenever stdout is not a TTY (which it never is
//! under a captured pipe), so a captured run MUST be free of ANSI escape bytes
//! regardless of `NO_COLOR`, and `NO_COLOR` must never *add* bytes.
//!
//! TRUTH: the embedded-corpus count is cross-checked against the very library
//! accessor the binary itself uses (`keyhog_core::embedded_detector_count`), so
//! the "Loaded N detectors" banner and the JSON array length are exact
//! equalities, not shape approximations.

use std::path::Path;
use std::process::Command;

const ESC: u8 = 0x1b;

struct Out {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Run the shipped binary in `dir` (its cwd), optionally forcing `NO_COLOR`
/// on (`Some(true)`) or explicitly removing it (`Some(false)`); `None` leaves
/// the inherited environment untouched. Returns raw bytes so byte-level
/// equality/escape checks are exact.
fn run(dir: &Path, no_color: Option<bool>, args: &[&str]) -> Out {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_keyhog"));
    cmd.current_dir(dir);
    match no_color {
        Some(true) => {
            cmd.env("NO_COLOR", "1");
        }
        Some(false) => {
            cmd.env_remove("NO_COLOR");
        }
        None => {}
    }
    let output = cmd
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawn keyhog {args:?}: {e}"));
    Out {
        code: output.status.code(),
        stdout: output.stdout,
        stderr: output.stderr,
    }
}

fn text(v: &[u8]) -> String {
    String::from_utf8_lossy(v).into_owned()
}

/// True iff the byte stream contains an ANSI escape (`0x1b`), the single byte
/// that opens every ANSI/SGR sequence. Its absence proves the stream is plain.
fn has_esc(v: &[u8]) -> bool {
    v.contains(&ESC)
}

// ---------------------------------------------------------------------------
// NO_COLOR / plain-stream contract
// ---------------------------------------------------------------------------

/// A captured (non-TTY) `detectors` listing is plain: zero ANSI escape bytes,
/// exits 0, and its banner is byte-exactly `Loaded {N} detectors (embedded):`
/// where N is the authoritative embedded corpus size. Running from an empty
/// temp cwd (no `./detectors` dir) forces the embedded corpus deterministically.
#[test]
fn detectors_listing_is_plain_and_banner_matches_embedded_count() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(dir.path(), Some(false), &["detectors"]);
    assert_eq!(
        out.code,
        Some(0),
        "detectors must exit 0; stderr={}",
        text(&out.stderr)
    );
    assert!(
        !has_esc(&out.stdout),
        "captured detectors stdout must contain no ANSI escape byte; got:\n{}",
        text(&out.stdout)
    );
    let stdout = text(&out.stdout);
    let first = stdout.lines().next().unwrap_or_default();
    let expected = format!(
        "Loaded {} detectors (embedded):",
        keyhog_core::embedded_detector_count()
    );
    assert_eq!(first, expected, "banner drift");
}

/// `NO_COLOR=1` must not change captured `detectors` output at all: with the
/// stream already plain (piped), the two runs are byte-for-byte identical, and
/// neither carries an escape byte. This is the host-independent color contract
///: never a silent add of ANSI when NO_COLOR is honored.
#[test]
fn no_color_does_not_alter_captured_detectors_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let with_nc = run(dir.path(), Some(true), &["detectors"]);
    let without_nc = run(dir.path(), Some(false), &["detectors"]);
    assert_eq!(with_nc.code, Some(0));
    assert_eq!(without_nc.code, Some(0));
    assert!(
        !has_esc(&with_nc.stdout),
        "NO_COLOR=1 output had an escape byte"
    );
    assert!(
        !has_esc(&without_nc.stdout),
        "plain output had an escape byte"
    );
    assert_eq!(
        with_nc.stdout, without_nc.stdout,
        "NO_COLOR=1 changed captured stdout bytes"
    );
}

/// `--version` is a plain, host-independent metadata banner: exit 0, no escape
/// bytes under capture, first line byte-exactly `KeyHog v{CARGO_PKG_VERSION}` of
/// the cli crate (which inherits the workspace version).
#[test]
fn version_banner_is_plain_and_exit_zero() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(dir.path(), Some(false), &["--version"]);
    assert_eq!(
        out.code,
        Some(0),
        "--version must exit 0; stderr={}",
        text(&out.stderr)
    );
    assert!(!has_esc(&out.stdout), "--version stdout had an escape byte");
    let stdout = text(&out.stdout);
    let first = stdout.lines().next().unwrap_or_default();
    assert_eq!(first, format!("KeyHog v{}", env!("CARGO_PKG_VERSION")));
}

/// `NO_COLOR` toggling leaves `--version` byte-identical (metadata banner never
/// colorizes under a pipe regardless of the env).
#[test]
fn version_bytes_identical_across_no_color_toggle() {
    let dir = tempfile::tempdir().expect("tempdir");
    let a = run(dir.path(), Some(true), &["-V"]);
    let b = run(dir.path(), Some(false), &["-V"]);
    assert_eq!(a.code, Some(0));
    assert_eq!(b.code, Some(0));
    assert_eq!(a.stdout, b.stdout, "NO_COLOR changed -V output bytes");
    assert!(!has_esc(&a.stdout));
}

/// `--help` is plain under capture (exit 0, no escapes) and carries the literal
/// `Usage:` block (clap must not leak color into a piped help stream).
#[test]
fn top_level_help_is_plain_with_usage() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(dir.path(), Some(false), &["--help"]);
    assert_eq!(out.code, Some(0), "--help must exit 0");
    assert!(!has_esc(&out.stdout), "--help stdout had an escape byte");
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("Usage:"),
        "help missing Usage: block:\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// --verbose (detectors) content contract
// ---------------------------------------------------------------------------

/// `detectors --verbose` prints the per-detector field labels
/// (`name:`/`service:`/`severity:`) that the grouped default view omits. Assert
/// the exact label columns the printer emits, plain, exit 0.
#[test]
fn detectors_verbose_emits_field_labels() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(dir.path(), Some(false), &["detectors", "--verbose"]);
    assert_eq!(out.code, Some(0), "stderr={}", text(&out.stderr));
    assert!(!has_esc(&out.stdout), "verbose stdout had an escape byte");
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("    name:      "),
        "missing name label:\n{stdout}"
    );
    assert!(stdout.contains("    service:   "), "missing service label");
    assert!(stdout.contains("    severity:  "), "missing severity label");
}

/// Negative twin: the DEFAULT (non-verbose) grouped listing must NOT contain the
/// verbose `name:` field label. It emits `  - <service> (...)` group headers and
/// `    - <id>` id rows instead. Proves `--verbose` is the sole gate on the
/// detail view.
#[test]
fn detectors_default_omits_verbose_field_labels() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(dir.path(), Some(false), &["detectors"]);
    assert_eq!(out.code, Some(0));
    let stdout = text(&out.stdout);
    assert!(
        !stdout.contains("    name:      "),
        "default grouped view leaked the verbose name label:\n{stdout}"
    );
    assert!(
        stdout.contains("    - "),
        "default view should list detector ids as `    - <id>` rows:\n{stdout}"
    );
}

/// The verbose block for a specific detector reproduces that detector's own
/// `name` exactly. Truth is drawn from the JSON surface (same corpus, same run
/// class), so the verbose text is pinned to a value the machine surface reports
/// rather than a hand-typed guess.
#[test]
fn detectors_verbose_block_matches_json_truth() {
    let dir = tempfile::tempdir().expect("tempdir");
    let json_out = run(dir.path(), Some(false), &["detectors", "--format", "json"]);
    assert_eq!(json_out.code, Some(0), "json listing must exit 0");
    let json_text = text(&json_out.stdout);
    let arr: Vec<serde_json::Value> =
        serde_json::from_str(&json_text).expect("detectors --format json must be a JSON array");
    assert!(!arr.is_empty(), "embedded corpus must be non-empty");
    let first = &arr[0];
    let id = first["id"].as_str().expect("id string").to_string();
    let name = first["name"].as_str().expect("name string").to_string();

    let verbose = run(
        dir.path(),
        Some(false),
        &["detectors", "--search", &id, "--verbose"],
    );
    assert_eq!(verbose.code, Some(0));
    let vtext = text(&verbose.stdout);
    assert!(
        vtext.contains(&id),
        "verbose output missing searched id `{id}`:\n{vtext}"
    );
    assert!(
        vtext.contains(&format!("    name:      {name}")),
        "verbose block for `{id}` must print `name:      {name}`:\n{vtext}"
    );
}

// ---------------------------------------------------------------------------
// --search boundary / JSON quiet-shape contracts
// ---------------------------------------------------------------------------

/// A `--search` needle that matches nothing yields EXACTLY empty stdout (the
/// listing short-circuits before printing the banner) and still exits 0. Concrete
/// byte assertion: stdout is the empty string.
#[test]
fn detectors_search_no_match_prints_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(
        dir.path(),
        Some(false),
        &["detectors", "--search", "zzq-no-such-detector-zzq"],
    );
    assert_eq!(out.code, Some(0), "stderr={}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "", "no-match search must print nothing");
}

/// The JSON surface for a no-match search is the empty array `[]\n` exactly 
/// the machine-readable "quiet" shape (no banner chatter, exit 0, no escapes).
#[test]
fn detectors_json_no_match_is_empty_array() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(
        dir.path(),
        Some(false),
        &[
            "detectors",
            "--format",
            "json",
            "--search",
            "zzq-no-such-detector-zzq",
        ],
    );
    assert_eq!(out.code, Some(0));
    assert!(!has_esc(&out.stdout), "json stdout had an escape byte");
    assert_eq!(
        text(&out.stdout),
        "[]\n",
        "empty JSON listing must be exactly `[]`"
    );
}

/// The full JSON listing length equals the authoritative embedded count, and the
/// first element carries the documented schema keys with the documented value
/// types (`verify` bool, `keywords` array). Exact count equality, not a shape
/// smoke test.
#[test]
fn detectors_json_length_and_schema_match_corpus() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(dir.path(), Some(false), &["detectors", "--format", "json"]);
    assert_eq!(out.code, Some(0));
    assert!(!has_esc(&out.stdout));
    let arr: Vec<serde_json::Value> = serde_json::from_str(&text(&out.stdout)).expect("json array");
    assert_eq!(
        arr.len(),
        keyhog_core::embedded_detector_count(),
        "JSON listing length must equal embedded corpus size"
    );
    let obj = arr[0].as_object().expect("first element is an object");
    for key in [
        "id",
        "name",
        "service",
        "severity",
        "keywords",
        "patterns",
        "companions",
        "verify",
    ] {
        assert!(obj.contains_key(key), "detector JSON missing key `{key}`");
    }
    assert!(obj["verify"].is_boolean(), "`verify` must be a JSON bool");
    assert!(
        obj["keywords"].is_array(),
        "`keywords` must be a JSON array"
    );
}

// ---------------------------------------------------------------------------
// --quiet / --verbose documentation surface (host-independent, cheap)
// ---------------------------------------------------------------------------

/// `detectors --help` documents the `--verbose` flag and its purpose. Pins the
/// operator-visible contract that `--verbose` exists on this subcommand.
#[test]
fn detectors_help_documents_verbose_flag() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(dir.path(), Some(false), &["detectors", "--help"]);
    assert_eq!(out.code, Some(0));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("--verbose"),
        "detectors --help missing --verbose:\n{stdout}"
    );
    assert!(
        stdout.contains("Print full detector spec"),
        "detectors --help missing --verbose doc:\n{stdout}"
    );
}

/// `calibrate-autoroute --help` documents the `--quiet` flag that suppresses the
/// per-probe progress chatter. Host-independent: `--help` short-circuits before
/// any probe spawns.
#[test]
fn calibrate_autoroute_help_documents_quiet_flag() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(dir.path(), Some(false), &["calibrate-autoroute", "--help"]);
    assert_eq!(out.code, Some(0));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("--quiet"),
        "calibrate-autoroute --help missing --quiet:\n{stdout}"
    );
    assert!(
        stdout.contains("Suppress the per-probe progress lines"),
        "calibrate-autoroute --help missing --quiet doc:\n{stdout}"
    );
}

/// `scan` owns `--quiet` (suppress the interactive stderr chrome) and
/// `--no-color`, but deliberately NOT `--verbose` (verbosity tiers are a
/// diagnostic-subcommand concern, not a scan concern). This guards both the
/// intentional presence of the two output-control flags and the intentional
/// absence of `--verbose`.
#[test]
fn scan_help_documents_quiet_and_no_color_but_not_verbose() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run(dir.path(), Some(false), &["scan", "--help"]);
    assert_eq!(out.code, Some(0));
    let stdout = text(&out.stdout);
    assert!(
        !stdout.contains("--verbose"),
        "scan --help unexpectedly lists --verbose:\n{stdout}"
    );
    assert!(
        stdout.contains("--quiet"),
        "scan --help must document --quiet:\n{stdout}"
    );
    assert!(
        stdout.contains("--no-color"),
        "scan --help must document --no-color:\n{stdout}"
    );
}

/// Adversarial: an unknown subcommand is a clap usage error, exit code 2, and
/// the error goes to a plain (escape-free) stderr under capture, unchanged by
/// `NO_COLOR`. Confirms color handling never corrupts the error path's exit
/// contract.
#[test]
fn unknown_subcommand_exits_two_with_plain_stderr() {
    let dir = tempfile::tempdir().expect("tempdir");
    let a = run(dir.path(), Some(true), &["definitely-not-a-subcommand"]);
    let b = run(dir.path(), Some(false), &["definitely-not-a-subcommand"]);
    assert_eq!(a.code, Some(2), "clap usage error must exit 2");
    assert_eq!(
        b.code,
        Some(2),
        "clap usage error must exit 2 regardless of NO_COLOR"
    );
    assert!(
        !has_esc(&a.stderr),
        "usage error stderr had an escape byte under NO_COLOR=1"
    );
    assert!(!has_esc(&b.stderr), "usage error stderr had an escape byte");
}
