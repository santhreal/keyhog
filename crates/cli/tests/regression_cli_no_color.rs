//! Regression contract for the CLI `scan` surface's color / `NO_COLOR`
//! behavior, driven through the REAL shipped binary (`env!("CARGO_BIN_EXE_keyhog")`)
//! as a child process with a *captured* (piped, non-TTY) stdout/stderr — exactly
//! the shape a script, CI redirect, or `NO_COLOR`-honoring terminal sees.
//!
//! WHY THIS IS HOST-INDEPENDENT (no accelerator assumed):
//!   * Every scan is pinned to `--backend cpu`, which is always available (the
//!     scalar engine never fails closed the way `--backend simd` does on a host
//!     without the Hyperscan prefilter). So these tests are green on accel and
//!     no-accel hosts alike.
//!   * The color contract itself is host-independent by construction: the text
//!     reporter (`keyhog_core::report::text`) and the CLI style layer resolve to
//!     the PLAIN (escape-free) palette whenever stdout is not a TTY — which it
//!     never is under a captured pipe (`reporting.rs`: `color = io::stdout().is_terminal()`).
//!     A captured run MUST therefore be free of ANSI escape bytes REGARDLESS of
//!     `NO_COLOR`, and `NO_COLOR` must never *add* bytes. That is the strongest
//!     honest observation available to a subprocess harness: color is auto-off
//!     under a pipe, so `NO_COLOR` on/off produces byte-identical plain output.
//!
//! TRUTH (values read from source, not guessed):
//!   * `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` has a valid CRC32 tail and
//!     fires `github-classic-pat` (`regression_cli_backend_matrix.rs`).
//!   * `AKIAQYLPMN5HFIQR7XYA` fires `aws-access-key` (same).
//!   * Findings present, none verified -> exit 1; clean scan -> exit 0; a bad
//!     `--backend` value -> exit 2 (clap user error).
//!   * `--verify` is opt-in (`args/scan.rs`), so without it every finding is
//!     unverified -> the text summary reads `N unverified` (never `N live`/`dead`),
//!     which needs no network and is deterministic.
//!   * The text reporter's non-empty summary is `"{N} secret[s] found"` joined by
//!     `" · "` with `"{U} unverified"` (`report/text.rs`); the empty summary is
//!     byte-exactly `No secrets detected in the scanned files.`. Secrets are
//!     redacted by default (`--show-secrets` off), so the raw token never appears.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use tempfile::TempDir;

const ESC: u8 = 0x1b;

/// A planted GitHub classic PAT with a valid CRC32 tail: fires
/// `github-classic-pat` on its own bytes.
const GHP: &str = "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";
const GHP_DETECTOR: &str = "github-classic-pat";

/// A planted AWS access-key id (no checksum): fires `aws-access-key`.
const AKIA: &str = "AKIAQYLPMN5HFIQR7XYA";
const AKIA_DETECTOR: &str = "aws-access-key";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Hermetic cache home so the autoroute cache never touches the dev host.
fn cache_home() -> TempDir {
    TempDir::new().expect("tempdir")
}

/// Write `content` to a fresh file, returning (owning dir, path).
fn fixture(name: &str, content: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join(name);
    std::fs::write(&path, content).expect("write fixture");
    (dir, path)
}

struct Out {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// The `NO_COLOR` environment posture for a run.
#[derive(Clone, Copy)]
enum Color {
    /// `NO_COLOR=1`: the operator explicitly disables color.
    NoColorOne,
    /// `NO_COLOR=""`: present but EMPTY. Per the no-color.org contract an empty
    /// value does NOT opt out (color stays enabled on a TTY); the variable
    /// disables color only when present AND non-empty. Under a pipe (as in these
    /// tests) output is plain regardless, so this posture is byte-identical to
    /// the others here; the empty-string rule itself lives in
    /// `style::no_color_requested`.
    NoColorEmpty,
    /// `NO_COLOR` removed from the child env — the default/"colored" posture.
    Removed,
}

/// Run `keyhog scan --no-daemon --backend cpu [--format F] <path>` under a
/// hermetic cache home with the requested `NO_COLOR` posture. Returns raw bytes
/// so byte-level escape / equality checks are exact.
fn scan(home: &Path, path: &Path, color: Color, format: Option<&str>) -> Out {
    let mut cmd = Command::new(binary());
    cmd.env("HOME", home).env("XDG_CACHE_HOME", home);
    match color {
        Color::NoColorOne => {
            cmd.env("NO_COLOR", "1");
        }
        Color::NoColorEmpty => {
            cmd.env("NO_COLOR", "");
        }
        Color::Removed => {
            cmd.env_remove("NO_COLOR");
        }
    }
    cmd.args(["scan", "--no-daemon", "--backend", "cpu"]);
    if let Some(f) = format {
        cmd.args(["--format", f]);
    }
    cmd.arg(path);
    let output = cmd.output().expect("spawn keyhog scan");
    Out {
        code: output.status.code(),
        stdout: output.stdout,
        stderr: output.stderr,
    }
}

fn text(v: &[u8]) -> String {
    String::from_utf8_lossy(v).into_owned()
}

/// True iff the byte stream contains an ANSI escape (`0x1b`) — the single byte
/// that opens every ANSI/SGR sequence. Its absence proves the stream is plain.
fn has_esc(v: &[u8]) -> bool {
    v.contains(&ESC)
}

/// Sorted detector-id multiset from a `--format json` report.
fn detector_ids(stdout: &[u8]) -> Vec<String> {
    let v: Value = serde_json::from_slice(stdout)
        .unwrap_or_else(|e| panic!("scan json stdout must parse ({e}); stdout={}", text(stdout)));
    let mut ids: Vec<String> = v
        .as_array()
        .expect("JSON report is a top-level array")
        .iter()
        .map(|f| {
            f.get("detector_id")
                .and_then(Value::as_str)
                .expect("every finding carries a detector_id string")
                .to_string()
        })
        .collect();
    ids.sort();
    ids
}

// ---------------------------------------------------------------------------
// Positive: NO_COLOR=1 text scan is plain and carries the concrete summary.
// ---------------------------------------------------------------------------

/// A `NO_COLOR=1` text scan over a planted PAT: exit 1, ZERO ANSI escape bytes
/// on stdout, and the concrete non-empty summary the reporter emits for a single
/// unverified finding (`1 secret found`, `1 unverified`). This is the core
/// `output.contains('\x1b') == false` contract on the human report path.
#[test]
fn no_color_text_scan_stdout_has_no_escape_and_concrete_summary() {
    let home = cache_home();
    let (_d, path) = fixture("leak.env", &format!("GITHUB_TOKEN={GHP}\n"));

    let out = scan(home.path(), &path, Color::NoColorOne, None);

    assert_eq!(
        out.code,
        Some(1),
        "planted secret, no --verify -> exit 1; stderr={}",
        text(&out.stderr)
    );
    assert_eq!(
        has_esc(&out.stdout),
        false,
        "NO_COLOR=1 text stdout must contain NO ANSI escape byte; stdout={}",
        text(&out.stdout)
    );
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("1 secret found"),
        "single finding must render `1 secret found`; stdout={stdout}"
    );
    assert!(
        stdout.contains("1 unverified"),
        "no --verify -> the finding is `1 unverified`; stdout={stdout}"
    );
    assert!(
        !stdout.contains("No secrets detected"),
        "a scan WITH a finding must NOT print the empty-summary line; stdout={stdout}"
    );
}

/// The exact joined summary token for one unverified finding is
/// `1 secret found · 1 unverified` (the reporter joins parts with ` · `). Pins
/// the precise string, not just its pieces.
#[test]
fn no_color_text_summary_is_exact_joined_token() {
    let home = cache_home();
    let (_d, path) = fixture("leak.env", &format!("GITHUB_TOKEN={GHP}\n"));

    let out = scan(home.path(), &path, Color::NoColorOne, None);
    assert_eq!(out.code, Some(1));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("1 secret found · 1 unverified"),
        "reporter must join summary parts with ` · `; stdout={stdout}"
    );
}

// ---------------------------------------------------------------------------
// Host-independence: default (NO_COLOR unset) piped output is ALSO plain.
// ---------------------------------------------------------------------------

/// With `NO_COLOR` REMOVED (the "colored" posture) a captured/piped text scan is
/// STILL plain — color auto-disables when stdout is not a TTY. Same exit code and
/// same concrete summary as the `NO_COLOR=1` run. Proves the color decision is
/// TTY-gated and host-independent under a pipe.
#[test]
fn default_env_piped_text_scan_is_also_plain() {
    let home = cache_home();
    let (_d, path) = fixture("leak.env", &format!("GITHUB_TOKEN={GHP}\n"));

    let out = scan(home.path(), &path, Color::Removed, None);

    assert_eq!(out.code, Some(1), "stderr={}", text(&out.stderr));
    assert_eq!(
        has_esc(&out.stdout),
        false,
        "piped stdout is plain even without NO_COLOR (TTY-gated); stdout={}",
        text(&out.stdout)
    );
    assert!(text(&out.stdout).contains("1 secret found"));
}

/// The CORE `NO_COLOR` guarantee: toggling `NO_COLOR` on/off never changes the
/// captured text-report bytes (both are plain under a pipe), so stdout is
/// byte-for-byte identical AND findings are therefore identical either way.
#[test]
fn no_color_toggle_yields_byte_identical_text_stdout() {
    let home = cache_home();
    let (_d, path) = fixture("leak.env", &format!("GITHUB_TOKEN={GHP}\n"));

    let with_nc = scan(home.path(), &path, Color::NoColorOne, None);
    let without_nc = scan(home.path(), &path, Color::Removed, None);

    assert_eq!(with_nc.code, Some(1));
    assert_eq!(without_nc.code, Some(1));
    assert_eq!(
        has_esc(&with_nc.stdout),
        false,
        "NO_COLOR=1 leaked an escape"
    );
    assert_eq!(
        has_esc(&without_nc.stdout),
        false,
        "default piped run leaked an escape"
    );
    assert_eq!(
        with_nc.stdout, without_nc.stdout,
        "NO_COLOR must not add/remove any byte from the captured text report"
    );
}

/// Under a pipe, `NO_COLOR=""` (present but EMPTY) yields a captured text report
/// byte-identical to `NO_COLOR=1` and carries no escape byte. NOTE: this identity
/// holds because color is TTY-gated OFF under a pipe for BOTH postures, not
/// because an empty `NO_COLOR` opts out. Per no-color.org an empty value does NOT
/// disable color on a TTY; that rule is enforced in `style::no_color_requested`
/// (`is_some_and(|v| !v.is_empty())`). A subprocess harness cannot exercise the
/// TTY branch, so this asserts only the pipe-level byte-identity it can honestly
/// observe.
#[test]
fn no_color_empty_value_piped_is_byte_identical_to_no_color_one() {
    let home = cache_home();
    let (_d, path) = fixture("leak.env", &format!("GITHUB_TOKEN={GHP}\n"));

    let one = scan(home.path(), &path, Color::NoColorOne, None);
    let empty = scan(home.path(), &path, Color::NoColorEmpty, None);

    assert_eq!(one.code, Some(1));
    assert_eq!(empty.code, Some(1));
    assert_eq!(
        has_esc(&empty.stdout),
        false,
        "NO_COLOR=\"\" leaked an escape"
    );
    assert_eq!(
        one.stdout, empty.stdout,
        "under a pipe both postures are plain (TTY-gated), so stdout is byte-identical"
    );
}

// ---------------------------------------------------------------------------
// Adversarial: the raw secret must never leak into the (redacted) report.
// ---------------------------------------------------------------------------

/// The text report REDACTS the credential by default (`--show-secrets` off): the
/// full raw token must NOT appear in stdout, yet the `Secret:` label row IS
/// present. Guards against a color/format regression accidentally echoing the
/// raw bytes. Plain (escape-free) under NO_COLOR.
#[test]
fn text_report_redacts_raw_token_but_keeps_secret_label() {
    let home = cache_home();
    let (_d, path) = fixture("leak.env", &format!("GITHUB_TOKEN={GHP}\n"));

    let out = scan(home.path(), &path, Color::NoColorOne, None);
    assert_eq!(out.code, Some(1));
    let stdout = text(&out.stdout);
    assert!(
        !stdout.contains(GHP),
        "the redacted text report must NOT contain the full raw token; stdout={stdout}"
    );
    assert!(
        stdout.contains("Secret:"),
        "the finding box must still carry the `Secret:` label; stdout={stdout}"
    );
    assert!(
        stdout.contains("Action:"),
        "the finding box must carry the remediation `Action:` label; stdout={stdout}"
    );
    assert_eq!(
        has_esc(&out.stdout),
        false,
        "redacted report leaked an escape"
    );
}

/// The remediation "next steps" block (numbered, non-empty) renders plainly on
/// the NO_COLOR path: the exact step-1 sentence appears with no escape byte.
#[test]
fn text_report_next_steps_render_plain() {
    let home = cache_home();
    let (_d, path) = fixture("leak.env", &format!("GITHUB_TOKEN={GHP}\n"));

    let out = scan(home.path(), &path, Color::NoColorOne, None);
    assert_eq!(out.code, Some(1));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("Revoke active secrets in the provider's dashboard."),
        "the numbered next-steps block must render; stdout={stdout}"
    );
    assert_eq!(has_esc(&out.stdout), false);
}

// ---------------------------------------------------------------------------
// Boundary: a clean file yields the exact empty-summary line, plain, exit 0.
// ---------------------------------------------------------------------------

/// A clean file's text report is byte-exactly the empty-summary line
/// (`No secrets detected in the scanned files.`), exits 0, carries NO escape, and
/// is identical across the `NO_COLOR` toggle.
#[test]
fn clean_file_empty_summary_is_plain_and_toggle_identical() {
    let home = cache_home();
    let (_d, path) = fixture("clean.txt", "the quick brown fox jumps over the lazy dog\n");

    let with_nc = scan(home.path(), &path, Color::NoColorOne, None);
    let without_nc = scan(home.path(), &path, Color::Removed, None);

    assert_eq!(with_nc.code, Some(0), "clean file -> exit 0");
    assert_eq!(without_nc.code, Some(0));
    assert!(
        text(&with_nc.stdout).contains("No secrets detected in the scanned files."),
        "clean scan must print the honest empty summary; stdout={}",
        text(&with_nc.stdout)
    );
    assert_eq!(
        has_esc(&with_nc.stdout),
        false,
        "clean NO_COLOR leaked escape"
    );
    assert_eq!(
        with_nc.stdout, without_nc.stdout,
        "clean-file report must be byte-identical across the NO_COLOR toggle"
    );
}

// ---------------------------------------------------------------------------
// Multi-detector: two secrets, plural summary, plain, both modes.
// ---------------------------------------------------------------------------

/// Two distinct planted secrets render the PLURAL summary `2 secrets found ·
/// 2 unverified`, plain, exit 1, on the NO_COLOR path.
#[test]
fn two_secrets_render_plural_summary_plain() {
    let home = cache_home();
    let content = format!("GITHUB_TOKEN={GHP}\nAWS_ACCESS_KEY_ID={AKIA}\n");
    let (_d, path) = fixture("multi.env", &content);

    let out = scan(home.path(), &path, Color::NoColorOne, None);

    assert_eq!(out.code, Some(1), "stderr={}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("2 secrets found · 2 unverified"),
        "two findings must render the plural joined summary; stdout={stdout}"
    );
    assert_eq!(
        has_esc(&out.stdout),
        false,
        "multi-secret report leaked escape"
    );
}

// ---------------------------------------------------------------------------
// JSON path: structured output never colorizes and is toggle-stable.
// ---------------------------------------------------------------------------

/// `--format json` is never colorized: no escape byte under either `NO_COLOR`
/// posture, byte-identical stdout across the toggle, and the detector-id set is
/// exactly `[github-classic-pat]`. The raw token never appears (redacted field).
#[test]
fn json_scan_is_plain_toggle_stable_and_has_exact_detector() {
    let home = cache_home();
    let (_d, path) = fixture("leak.env", &format!("GITHUB_TOKEN={GHP}\n"));

    let with_nc = scan(home.path(), &path, Color::NoColorOne, Some("json"));
    let without_nc = scan(home.path(), &path, Color::Removed, Some("json"));

    assert_eq!(with_nc.code, Some(1));
    assert_eq!(without_nc.code, Some(1));
    assert_eq!(
        has_esc(&with_nc.stdout),
        false,
        "json NO_COLOR leaked escape"
    );
    assert_eq!(
        has_esc(&without_nc.stdout),
        false,
        "json default piped leaked escape"
    );
    assert_eq!(
        with_nc.stdout, without_nc.stdout,
        "json report must be byte-identical across the NO_COLOR toggle"
    );
    assert_eq!(
        detector_ids(&with_nc.stdout),
        vec![GHP_DETECTOR.to_string()],
        "json must carry exactly one github-classic-pat finding"
    );
    assert!(
        !text(&with_nc.stdout).contains(GHP),
        "json report carries the hash/redacted form, never the raw token"
    );
}

/// Two-secret `--format json` detector set is exactly `[aws-access-key,
/// github-classic-pat]` (sorted), identical across the NO_COLOR toggle, escape-free.
#[test]
fn json_two_secret_detector_set_is_toggle_stable() {
    let home = cache_home();
    let content = format!("GITHUB_TOKEN={GHP}\nAWS_ACCESS_KEY_ID={AKIA}\n");
    let (_d, path) = fixture("multi.env", &content);

    let with_nc = scan(home.path(), &path, Color::NoColorOne, Some("json"));
    let without_nc = scan(home.path(), &path, Color::Removed, Some("json"));

    assert_eq!(with_nc.code, Some(1));
    assert_eq!(
        detector_ids(&with_nc.stdout),
        vec![AKIA_DETECTOR.to_string(), GHP_DETECTOR.to_string()],
        "json must surface BOTH planted detectors, sorted"
    );
    assert_eq!(
        with_nc.stdout, without_nc.stdout,
        "two-secret json must be byte-identical across NO_COLOR toggle"
    );
    assert_eq!(has_esc(&with_nc.stdout), false);
}

// ---------------------------------------------------------------------------
// stderr / error-path color contract.
// ---------------------------------------------------------------------------

/// The scan's stderr (end-of-scan chatter / skip summary) carries no ANSI escape
/// byte under a pipe, under EITHER `NO_COLOR` posture — color never leaks onto
/// the diagnostic stream a CI log captures.
#[test]
fn scan_stderr_has_no_escape_across_toggle() {
    let home = cache_home();
    let content = format!("GITHUB_TOKEN={GHP}\nAWS_ACCESS_KEY_ID={AKIA}\n");
    let (_d, path) = fixture("multi.env", &content);

    let with_nc = scan(home.path(), &path, Color::NoColorOne, None);
    let without_nc = scan(home.path(), &path, Color::Removed, None);

    assert_eq!(
        has_esc(&with_nc.stderr),
        false,
        "NO_COLOR=1 scan stderr had an escape byte; stderr={}",
        text(&with_nc.stderr)
    );
    assert_eq!(
        has_esc(&without_nc.stderr),
        false,
        "default piped scan stderr had an escape byte; stderr={}",
        text(&without_nc.stderr)
    );
}

/// Adversarial: a bad `--backend` value fails closed at clap parse time — exit 2,
/// naming the rejected value on a plain (escape-free) stderr, unchanged by
/// `NO_COLOR`. Confirms the color layer never corrupts the user-error exit path.
#[test]
fn bad_backend_value_exits_two_with_plain_stderr_both_modes() {
    let home = cache_home();
    let (_d, path) = fixture("leak.env", &format!("GITHUB_TOKEN={GHP}\n"));

    // Deliberately invalid backend so clap rejects it before any scan runs.
    let run = |color: Color| -> Out {
        let mut cmd = Command::new(binary());
        cmd.env("HOME", home.path())
            .env("XDG_CACHE_HOME", home.path());
        match color {
            Color::NoColorOne => {
                cmd.env("NO_COLOR", "1");
            }
            Color::NoColorEmpty => {
                cmd.env("NO_COLOR", "");
            }
            Color::Removed => {
                cmd.env_remove("NO_COLOR");
            }
        }
        let output = cmd
            .args(["scan", "--no-daemon", "--backend", "turbo"])
            .arg(&path)
            .output()
            .expect("spawn keyhog scan");
        Out {
            code: output.status.code(),
            stdout: output.stdout,
            stderr: output.stderr,
        }
    };

    let a = run(Color::NoColorOne);
    let b = run(Color::Removed);

    assert_eq!(a.code, Some(2), "bad --backend must exit 2 (user error)");
    assert_eq!(b.code, Some(2), "exit 2 regardless of NO_COLOR");
    assert_eq!(
        has_esc(&a.stderr),
        false,
        "usage-error stderr had an escape byte under NO_COLOR=1; stderr={}",
        text(&a.stderr)
    );
    assert_eq!(
        has_esc(&b.stderr),
        false,
        "usage-error stderr had an escape byte"
    );
    assert!(
        text(&a.stderr).contains("turbo"),
        "the parser error must name the rejected `turbo` value; stderr={}",
        text(&a.stderr)
    );
}
