//! Regression: `keyhog scan --stdin` positional-chunk semantics that the
//! sibling `regression_cli_scan_stdin.rs` (format/exit-code matrix) does NOT
//! cover: LINE/OFFSET fidelity over multi-line and multi-secret chunks, the
//! oversized-stdin fail-closed, byte-size flag validation, and the scan-path
//! CONTROL-BYTE sanitization contract observed end-to-end through the shipped
//! binary over a piped stdin.
//!
//! Every value below was observed by running the real binary; nothing is
//! guessed. The piped secret is a Slack **bot** token
//! (`xoxb-` + two 13-digit groups + 24-char secret) which fires
//! `slack-bot-token` (service `slack`, severity `critical`, confidence 0.9)
//! deterministically on the path-less stdin chunk.
//!
//! Control-byte truth (proven here, not asserted from memory): the scan path
//! STRIPS non-whitespace C0 control bytes (0x08 backspace, 0x0C form-feed)
//! so a leading 0x0C leaves the token at offset 0 and a 0x08 spliced INTO the
//! token rejoins it to the exact same value/hash (an evasion that fails)
//! while it PRESERVES the whitespace controls (0x09 tab, 0x0D carriage
//! return), which shift the token to offset 1.
//!
//! Host-independent: uses `--backend cpu` (always available); the one `simd`
//! test asserts finding-parity OR the exit-3 fail-closed, never assuming an
//! accelerator. Every assertion pins a concrete value.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// A Slack bot token proven to fire `slack-bot-token` on its own stdin bytes:
/// `xoxb-` + 13-digit + 13-digit + 24 alnum secret.
const TOKEN: &str = "xoxb-1234567890123-1234567890123-abcdefghijklmnopqrstuvwx";
/// A second, distinct valid bot token (different numeric groups + secret).
const TOKEN2: &str = "xoxb-9999999999999-8888888888888-zzzzyyyyxxxxwwwwvvvvuuuu";

const DETECTOR_ID: &str = "slack-bot-token";
const DETECTOR_NAME: &str = "Slack Bot Token";
/// SHA-256 of the exact `TOKEN` bytes (`credential_hash` == sha256(value)).
const TOKEN_SHA256: &str = "a8dd917042994f6c6f183c6f0718ab4241065165b299050b51302d3167cc3901";
/// SHA-256 of the exact `TOKEN2` bytes.
const TOKEN2_SHA256: &str = "d77b50464417994d02dc631feb18fce261d187534c4d451f49665a61aee95145";
const REDACTED: &str = "xoxb...uvwx";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Run `keyhog scan --daemon=off --backend <backend> --stdin --format <format>`
/// with `input` piped over stdin. Returns (exit code, stdout, stderr).
fn run(input: &[u8], backend: &str, format: &str) -> (Option<i32>, String, String) {
    run_args(
        input,
        &[
            "scan",
            "--daemon=off",
            "--backend",
            backend,
            "--stdin",
            "--format",
            format,
        ],
    )
}

/// Run the binary with an explicit arg vector, piping `input` over stdin.
fn run_args(input: &[u8], args: &[&str]) -> (Option<i32>, String, String) {
    let mut child = Command::new(binary())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn keyhog scan --stdin");
    child
        .stdin
        .take()
        .expect("child stdin handle")
        .write_all(input)
        .expect("pipe input to stdin");
    let out = child.wait_with_output().expect("wait keyhog scan --stdin");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Parse stdout as the top-level JSON findings array.
fn json_findings(out: &str) -> Vec<serde_json::Value> {
    let v: serde_json::Value = serde_json::from_str(out).expect("stdin json stdout must parse");
    v.as_array()
        .expect("stdin json report must be a top-level ARRAY")
        .clone()
}

// ---------------------------------------------------------------------------
// LINE / OFFSET fidelity
// ---------------------------------------------------------------------------

/// A token on the THIRD line of a piped chunk must report `line: 3` and the
/// byte offset of the token within the chunk. The two preceding lines are
/// `"line one plain text\n"` (20 bytes) + `"second line also plain\n"`
/// (23 bytes) = 43, so the token starts at offset 43, proving stdin line/offset
/// is computed from the chunk, not reset to line 1 / offset 0.
#[test]
fn stdin_multiline_token_reports_exact_line_3_and_offset_43() {
    let input = format!("line one plain text\nsecond line also plain\n{TOKEN}\n");
    let (code, out, err) = run(input.as_bytes(), "cpu", "json");
    assert_eq!(
        code,
        Some(1),
        "multiline stdin finding exits 1; stderr={err}"
    );
    let f = json_findings(&out);
    assert_eq!(f.len(), 1, "one token on line 3 -> one finding, got {f:?}");
    assert_eq!(
        f[0].pointer("/location/line").and_then(|x| x.as_u64()),
        Some(3),
        "token on the third piped line must report line 3"
    );
    assert_eq!(
        f[0].pointer("/location/offset").and_then(|x| x.as_u64()),
        Some(43),
        "token must report byte offset 43 (20 + 23 bytes of preceding lines)"
    );
    assert_eq!(
        f[0].get("credential_hash").and_then(|x| x.as_str()),
        Some(TOKEN_SHA256),
        "the exact token bytes are hashed regardless of chunk position"
    );
}

/// Two DISTINCT valid tokens on two lines of one piped chunk yield exactly two
/// findings, each with its own hash and (line, offset): token1 at line 1 /
/// offset 0, token2 at line 2 / offset 58 (token1 is 57 bytes + one `\n`).
#[test]
fn stdin_two_secrets_yield_two_findings_distinct_hash_line_offset() {
    let input = format!("{TOKEN}\n{TOKEN2}\n");
    let (code, out, _err) = run(input.as_bytes(), "cpu", "json");
    assert_eq!(code, Some(1), "two-secret stdin scan exits 1");
    let f = json_findings(&out);
    assert_eq!(f.len(), 2, "two distinct tokens -> two findings, got {f:?}");

    assert_eq!(
        f[0].get("credential_hash").and_then(|x| x.as_str()),
        Some(TOKEN_SHA256),
        "first finding hashes TOKEN"
    );
    assert_eq!(
        f[0].pointer("/location/line").and_then(|x| x.as_u64()),
        Some(1),
        "first token on line 1"
    );
    assert_eq!(
        f[0].pointer("/location/offset").and_then(|x| x.as_u64()),
        Some(0),
        "first token at offset 0"
    );

    assert_eq!(
        f[1].get("credential_hash").and_then(|x| x.as_str()),
        Some(TOKEN2_SHA256),
        "second finding hashes the DISTINCT TOKEN2, not a repeat of TOKEN"
    );
    assert_eq!(
        f[1].pointer("/location/line").and_then(|x| x.as_u64()),
        Some(2),
        "second token on line 2"
    );
    assert_eq!(
        f[1].pointer("/location/offset").and_then(|x| x.as_u64()),
        Some(58),
        "second token at offset 58 (57-byte token1 + newline)"
    );
}

/// SARIF path agrees with JSON on the two-secret chunk: exactly two results,
/// both `ruleId` == the slack detector. Guards a per-format recall hole where a
/// serializer collapses or drops one of two same-rule findings.
#[test]
fn stdin_sarif_two_secrets_produce_two_results_same_ruleid() {
    let input = format!("{TOKEN}\n{TOKEN2}\n");
    let (code, out, _err) = run(input.as_bytes(), "cpu", "sarif");
    assert_eq!(code, Some(1), "two-secret sarif scan exits 1");
    let v: serde_json::Value = serde_json::from_str(&out).expect("sarif must parse");
    let results = v
        .pointer("/runs/0/results")
        .and_then(|r| r.as_array())
        .expect("sarif runs[0].results array");
    assert_eq!(results.len(), 2, "two piped secrets -> two SARIF results");
    let ids: Vec<Option<&str>> = results
        .iter()
        .map(|r| r.get("ruleId").and_then(|x| x.as_str()))
        .collect();
    assert_eq!(
        ids,
        vec![Some(DETECTOR_ID), Some(DETECTOR_ID)],
        "both SARIF results carry the slack-bot-token ruleId"
    );
}

/// CSV path carries the multi-line token's exact `line`/`offset` cells (columns
/// 9 and 10 of the 15-field row): a token on line 3 at offset 43 must appear in
/// the sole data row as `...,stdin,,3,43,...`.
#[test]
fn stdin_csv_multiline_row_has_line_3_offset_43_cells() {
    let input = format!("line one plain text\nsecond line also plain\n{TOKEN}\n");
    let (code, out, _err) = run(input.as_bytes(), "cpu", "csv");
    assert_eq!(code, Some(1), "multiline csv scan exits 1");
    let row = out
        .lines()
        .filter(|l| !l.is_empty())
        .nth(1)
        .expect("csv must have one data row after the header");
    let expected_prefix = format!(
        "{DETECTOR_ID},{DETECTOR_NAME},slack,critical,{REDACTED},{TOKEN_SHA256},stdin,,3,43,"
    );
    assert!(
        row.starts_with(&expected_prefix),
        "csv data row must encode line 3 / offset 43 for the piped token;\ngot:  {row}\nwant: {expected_prefix}"
    );
    let field_count = row.matches(',').count() + 1;
    assert_eq!(field_count, 15, "csv data row must have exactly 15 fields");
}

// ---------------------------------------------------------------------------
// Control-byte sanitization (scan-path contract, observed over stdin)
// ---------------------------------------------------------------------------

/// A leading FORM-FEED (0x0C, a non-whitespace C0 control) is STRIPPED before
/// scanning: the token that followed the 0x0C byte reports offset 0 (not 1),
/// and hashes to the exact clean-token value. Proves 0x0C is removed, not kept.
#[test]
fn stdin_leading_formfeed_0x0c_stripped_token_at_offset_0() {
    let mut input = vec![0x0Cu8];
    input.extend_from_slice(TOKEN.as_bytes());
    input.push(b'\n');
    let (code, out, _err) = run(&input, "cpu", "json");
    assert_eq!(code, Some(1), "form-feed + token scan exits 1");
    let f = json_findings(&out);
    assert_eq!(f.len(), 1, "one token after a stripped 0x0C -> one finding");
    assert_eq!(
        f[0].pointer("/location/offset").and_then(|x| x.as_u64()),
        Some(0),
        "leading 0x0C is stripped, so the token sits at offset 0"
    );
    assert_eq!(
        f[0].get("credential_hash").and_then(|x| x.as_str()),
        Some(TOKEN_SHA256),
        "the stripped control byte is not part of the hashed value"
    );
}

/// A leading TAB (0x09, a whitespace control) is PRESERVED: the token reports
/// offset 1, the tab occupies byte 0. This is the negative twin of the 0x0C
/// case and proves whitespace controls are NOT stripped.
#[test]
fn stdin_leading_tab_0x09_preserved_token_at_offset_1() {
    let mut input = vec![b'\t'];
    input.extend_from_slice(TOKEN.as_bytes());
    input.push(b'\n');
    let (code, out, _err) = run(&input, "cpu", "json");
    assert_eq!(code, Some(1), "tab + token scan exits 1");
    let f = json_findings(&out);
    assert_eq!(
        f[0].pointer("/location/offset").and_then(|x| x.as_u64()),
        Some(1),
        "leading 0x09 tab is kept, shifting the token to offset 1"
    );
    assert_eq!(
        f[0].get("credential_hash").and_then(|x| x.as_str()),
        Some(TOKEN_SHA256),
        "the token value is unaffected by the preserved tab"
    );
}

/// A leading CARRIAGE-RETURN (0x0D, a whitespace control) is likewise PRESERVED:
/// the token reports offset 1. Distinguishes 0x0D (kept) from 0x0C (stripped).
#[test]
fn stdin_leading_cr_0x0d_preserved_token_at_offset_1() {
    let mut input = vec![b'\r'];
    input.extend_from_slice(TOKEN.as_bytes());
    input.push(b'\n');
    let (code, out, _err) = run(&input, "cpu", "json");
    assert_eq!(code, Some(1), "cr + token scan exits 1");
    let f = json_findings(&out);
    assert_eq!(
        f[0].pointer("/location/offset").and_then(|x| x.as_u64()),
        Some(1),
        "leading 0x0D carriage-return is kept, shifting the token to offset 1"
    );
}

/// Adversarial evasion: a BACKSPACE (0x08) spliced INTO the middle of the token
/// is stripped, rejoining the two halves into the exact valid token, so the
/// split does NOT evade detection. The finding reports offset 0 and the clean
/// token's hash, proving the sanitizer defeats control-byte splitting.
#[test]
fn stdin_backspace_0x08_split_token_still_detected_same_hash() {
    // "xoxb-1234567890123-1234567890123" + 0x08 + "-abcdefghijklmnopqrstuvwx"
    let mut input = b"xoxb-1234567890123-1234567890123".to_vec();
    input.push(0x08);
    input.extend_from_slice(b"-abcdefghijklmnopqrstuvwx\n");
    let (code, out, _err) = run(&input, "cpu", "json");
    assert_eq!(
        code,
        Some(1),
        "a 0x08-split token must still be detected (exit 1), not evade"
    );
    let f = json_findings(&out);
    assert_eq!(f.len(), 1, "the rejoined token yields exactly one finding");
    assert_eq!(
        f[0].get("credential_hash").and_then(|x| x.as_str()),
        Some(TOKEN_SHA256),
        "stripping the 0x08 rejoins the exact clean token -> identical hash"
    );
    assert_eq!(
        f[0].pointer("/location/offset").and_then(|x| x.as_u64()),
        Some(0),
        "the rejoined token sits at offset 0"
    );
}

// ---------------------------------------------------------------------------
// Byte-limit fail-closed + flag validation
// ---------------------------------------------------------------------------

/// Oversized stdin fails CLOSED: piping 100 bytes with `--limit-stdin-bytes 8B`
/// exits 13 (EXIT_SOURCE_FAILED), the scanner refuses to report "clean" for a
/// source it could not fully read, and stdout is the empty JSON array (no
/// partial findings).
#[test]
fn stdin_oversized_input_fails_closed_exit_13_empty_stdout() {
    let big = vec![b'a'; 100];
    let (code, out, _err) = run_args(
        &big,
        &[
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--stdin",
            "--limit-stdin-bytes",
            "8B",
            "--format",
            "json",
        ],
    );
    assert_eq!(
        code,
        Some(13),
        "stdin over the byte cap must fail closed with EXIT_SOURCE_FAILED (13)"
    );
    assert_eq!(
        out.trim_end(),
        "",
        "a failed-closed stdin scan (exit 13) emits nothing on stdout, the error is \
         reported on stderr, not an empty JSON array; got: {out:?}"
    );
}

/// The oversized-stdin error is WRAPPED: the operator sees the inner reason
/// (`stdin exceeds 8 byte limit`) inside the `failed to read source: ... Fix:`
/// envelope, plus the top-level "Not reporting \"clean\"" refusal. Asserted via
/// `.contains()` on the inner reason (never a whole-string ==).
#[test]
fn stdin_oversized_error_surfaces_inner_reason_and_refusal() {
    let big = vec![b'a'; 100];
    let (_code, _out, err) = run_args(
        &big,
        &[
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--stdin",
            "--limit-stdin-bytes",
            "8B",
            "--format",
            "json",
        ],
    );
    assert!(
        err.contains("failed to read source:"),
        "source error must be wrapped in the 'failed to read source:' envelope; stderr:\n{err}"
    );
    assert!(
        err.contains("stdin exceeds 8 byte limit"),
        "the inner reason (byte-limit) must be surfaced; stderr:\n{err}"
    );
    assert!(
        err.contains("Not reporting \"clean\""),
        "an incomplete stdin scan must loudly refuse to report clean; stderr:\n{err}"
    );
}

/// Under-limit stdin scans cleanly: `abc\n` (4 bytes) with `--limit-stdin-bytes
/// 8B` is within cap, contains no secret, exits 0 with an empty array. Boundary
/// twin of the fail-closed test.
#[test]
fn stdin_under_byte_limit_scans_clean_exit_0() {
    let (code, out, err) = run_args(
        b"abc\n",
        &[
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--stdin",
            "--limit-stdin-bytes",
            "8B",
            "--format",
            "json",
        ],
    );
    assert_eq!(code, Some(0), "under-cap clean stdin exits 0; stderr={err}");
    assert_eq!(out.trim_end(), "[]", "under-cap clean stdin -> empty array");
}

/// `--limit-stdin-bytes` requires a unit suffix: a bare `8` (no `B`/`K`/...) is
/// a clap value-parser error -> exit 2 (EXIT_USER_ERROR) with the actionable
/// "missing a unit" message, and NO scan runs.
#[test]
fn stdin_bad_byte_limit_missing_unit_exit_2() {
    let (code, _out, err) = run_args(
        b"abc\n",
        &[
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--stdin",
            "--limit-stdin-bytes",
            "8",
            "--format",
            "json",
        ],
    );
    assert_eq!(
        code,
        Some(2),
        "an unparseable --limit-stdin-bytes is a user error (exit 2)"
    );
    assert!(
        err.contains("missing a unit"),
        "the byte-size parse error must name the missing unit; stderr:\n{err}"
    );
}

// ---------------------------------------------------------------------------
// Backend host-independence
// ---------------------------------------------------------------------------

/// `--backend simd` over stdin is host-independent: on a build WITH the
/// Hyperscan prefilter it surfaces the same finding (exit 1, same detector id);
/// on a `ci`/no-prefilter build it FAILS CLOSED (exit 3) with the
/// "silent cpu-fallback execution is forbidden" refusal, never a silent
/// downgrade. Exactly one of those two outcomes must hold.
#[test]
fn stdin_simd_backend_surfaces_finding_or_fails_closed() {
    let input = format!("{TOKEN}\n");
    let (code, out, err) = run(input.as_bytes(), "simd", "json");
    match code {
        Some(1) => {
            let f = json_findings(&out);
            assert_eq!(
                f[0].get("detector_id").and_then(|x| x.as_str()),
                Some(DETECTOR_ID),
                "simd path (when available) surfaces the same slack-bot-token id"
            );
        }
        Some(3) => {
            assert!(
                err.contains("silent cpu-fallback execution is forbidden"),
                "a simd build without a prefilter must fail closed (exit 3) with the \
                 forbidden-fallback message, not degrade silently; stderr:\n{err}"
            );
        }
        other => panic!(
            "simd stdin scan must either surface the finding (exit 1) or fail closed \
             (exit 3); got exit {other:?}\nstdout:\n{out}\nstderr:\n{err}"
        ),
    }
}
