//! Regression coverage for the stdin source (`crates/sources/src/stdin.rs`).
//!
//! The existing stdin tests (`regression_input_sources_matrix.rs`,
//! `adversarial/stdin_over_max_size_counted.rs`) all exercise the *internal*
//! read helper (`testing::TestApi::read_stdin_test_input_with_limit`) and only
//! observe the decoded `String`. None of them drives the **public
//! `Source::chunks()` API** or asserts the emitted `Chunk` / `ChunkMetadata`.
//!
//! This file closes that gap. Because `StdinSource::chunks()` reads the real
//! process stdin (and would block on a TTY), the chunk-level assertions run in
//! a re-exec harness: a parent test spawns *this same test binary* with a
//! controlled stdin pipe and `--exact --ignored <child>`, then asserts on the
//! child's process exit code (0 = all child assertions passed, 101 = a child
//! assertion panicked). The `#[ignore]`d child bodies never run during a normal
//! `cargo test` (so they never block on real stdin); only the parent invokes
//! them with a closed pipe.

use keyhog_core::{Source, SourceError};
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{SourceLimits, StdinSource};

// ---------------------------------------------------------------------------
// Decode-level truths (deterministic; no process stdin involved).
// These target byte shapes not already covered by the input-sources matrix
// (NUL, CRLF, zero-byte cap, multibyte UTF-8, bulk payloads).
// ---------------------------------------------------------------------------

#[test]
fn stdin_nul_byte_survives_decode() {
    // 0x00 is valid UTF-8 (a C0 control), so it must pass through verbatim -
    // secrets embedded in NUL-delimited env dumps stay scannable.
    let out = TestApi
        .read_stdin_test_input_with_limit(b"tok\x00en", 1024)
        .expect("NUL-containing stdin is valid UTF-8 and must decode");
    assert_eq!(out, "tok\u{0}en");
    assert_eq!(out.len(), 6);
    assert_eq!(out.as_bytes()[3], 0u8);
}

#[test]
fn stdin_crlf_bytes_preserved() {
    // Windows line endings must not be normalized away; the scanner needs the
    // exact byte content to compute accurate offsets.
    let out = TestApi
        .read_stdin_test_input_with_limit(b"a\r\nb", 1024)
        .expect("CRLF stdin under the cap must decode verbatim");
    assert_eq!(out, "a\r\nb");
    assert_eq!(out.len(), 4);
}

#[test]
fn stdin_zero_limit_rejects_any_byte() {
    // cap == 0 means read_to_cap reads 1 byte, sees len (1) > cap (0), and
    // fails loud rather than silently truncating to empty.
    let err = TestApi
        .read_stdin_test_input_with_limit(b"x", 0)
        .expect_err("a zero-byte cap must reject any non-empty stdin");
    assert_eq!(err.kind(), std::io::ErrorKind::Other);
    assert_eq!(err.to_string(), "stdin exceeds 0 byte limit");
}

#[test]
fn stdin_zero_limit_accepts_empty_input() {
    // The boundary twin of the previous test: empty input at cap 0 is len 0,
    // which is NOT > cap, so it succeeds as the empty string.
    let out = TestApi
        .read_stdin_test_input_with_limit(b"", 0)
        .expect("empty stdin at a zero cap is exactly at the limit, not over");
    assert_eq!(out, "");
    assert_eq!(out.len(), 0);
}

#[test]
fn stdin_empty_input_decodes_to_empty_string() {
    let out = TestApi
        .read_stdin_test_input_with_limit(b"", 1024)
        .expect("empty stdin under a normal cap decodes to the empty string");
    assert_eq!(out, "");
    assert_eq!(out.len(), 0);
}

#[test]
fn stdin_multibyte_utf8_survives() {
    // Multibyte code points (accent + emoji) must round-trip; a naive
    // byte-count cap must not split them, and the trailing secret survives.
    let input = "café🔑=sk_live_ZZ".as_bytes();
    let out = TestApi
        .read_stdin_test_input_with_limit(input, 1024)
        .expect("valid multibyte UTF-8 under the cap decodes verbatim");
    assert_eq!(out, "café🔑=sk_live_ZZ");
    assert_eq!(out.chars().count(), 16);
    assert_eq!(out.len(), 20);
}

#[test]
fn stdin_bulk_payload_under_limit_roundtrips() {
    // 100 KiB of 'A' well under the 10 MiB default must be returned whole,
    // proving the cap only bounds oversize input, not ordinary bulk stdin.
    let input = vec![b'A'; 100_000];
    let out = TestApi
        .read_stdin_test_input_with_limit(&input, 10 * 1024 * 1024)
        .expect("a 100 KiB payload under a 10 MiB cap must decode whole");
    assert_eq!(out.len(), 100_000);
    assert_eq!(out.as_bytes()[0], b'A');
    assert_eq!(out.as_bytes()[99_999], b'A');
    assert!(out.bytes().all(|b| b == b'A'));
}

#[test]
fn stdin_truncation_increments_over_max_size_counter_exactly_once() {
    // The over-cap failure is a loud, counted skip (Law 10), and an in-cap
    // read must leave the telemetry at zero. Held under an exclusive scan
    // scope so the process-global counter this asserts on is not polluted.
    let _guard = TestApi.skip_counter_guard();

    TestApi.reset_skip_counters();
    let err = TestApi
        .read_stdin_test_input_with_limit(b"toolong", 3)
        .expect_err("7 bytes over a 3-byte cap must fail loud");
    assert_eq!(err.to_string(), "stdin exceeds 3 byte limit");
    assert_eq!(keyhog_sources::skip_counts().over_max_size, 1);

    TestApi.reset_skip_counters();
    let ok = TestApi
        .read_stdin_test_input_with_limit(b"ok", 3)
        .expect("2 bytes under a 3-byte cap must succeed");
    assert_eq!(ok, "ok");
    assert_eq!(keyhog_sources::skip_counts().over_max_size, 0);
}

// ---------------------------------------------------------------------------
// Public source-label contract.
// ---------------------------------------------------------------------------

#[test]
fn configured_stdin_source_name_is_stdin() {
    // The builder-configured variant must keep the same "stdin" telemetry
    // label as the plain source; findings/reporters key off it.
    let configured = StdinSource.with_limits(SourceLimits::default());
    assert_eq!(configured.name(), "stdin");
}

// ---------------------------------------------------------------------------
// Public `Source::chunks()` contract, driven through a controlled stdin pipe.
// The child bodies below are `#[ignore]`d harness targets: they read the real
// process stdin and are only ever launched by the parent tests that follow.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "harness child: launched by a parent test with a controlled stdin pipe; reads real process stdin so it is skipped in normal runs"]
fn stdin_child_default_source_single_chunk() {
    // Assert the full emitted chunk: exact bytes (== KEYHOG_TEST_STDIN_EXPECT),
    // the "stdin" source label, and the whole-file metadata constants.
    let expected = std::env::var("KEYHOG_TEST_STDIN_EXPECT").unwrap_or_default();

    let rows: Vec<_> = StdinSource.chunks().collect();
    assert_eq!(
        rows.len(),
        1,
        "stdin source must emit exactly one chunk row"
    );

    let chunk = match rows.into_iter().next().unwrap() {
        Ok(chunk) => chunk,
        Err(err) => panic!("stdin chunk must be Ok, got {err:?}"),
    };

    assert_eq!(&*chunk.data, expected.as_str());
    assert_eq!(chunk.metadata.source_type, "stdin");
    assert_eq!(chunk.metadata.base_offset, 0);
    assert_eq!(chunk.metadata.base_line, 0);
    assert_eq!(chunk.metadata.path, None);
    assert_eq!(chunk.metadata.commit, None);
    assert_eq!(chunk.metadata.author, None);
    assert_eq!(chunk.metadata.date, None);
    assert_eq!(chunk.metadata.mtime_ns, None);
    assert_eq!(chunk.metadata.size_bytes, None);
    assert_eq!(chunk.metadata.decoded_span, None);
}

#[test]
#[ignore = "harness child: launched by a parent test that pipes oversized stdin against a tiny configured cap"]
fn stdin_child_configured_source_over_limit_errs() {
    // The public builder path (`with_limits`) must surface an oversize stdin as
    // one `SourceError::Io` row with the exact byte-limit message, not silently
    // truncate.
    let limit: usize = std::env::var("KEYHOG_TEST_STDIN_LIMIT")
        .expect("KEYHOG_TEST_STDIN_LIMIT must be set by the parent test")
        .parse()
        .expect("KEYHOG_TEST_STDIN_LIMIT must parse as usize");

    let limits = SourceLimits {
        stdin_bytes: limit,
        ..SourceLimits::default()
    };

    let rows: Vec<_> = StdinSource.with_limits(limits).chunks().collect();
    assert_eq!(
        rows.len(),
        1,
        "stdin source must emit exactly one row even on the error path"
    );

    let err = match rows.into_iter().next().unwrap() {
        Ok(chunk) => panic!(
            "expected an oversize error, got a {}-byte chunk",
            chunk.data.len()
        ),
        Err(err) => err,
    };

    assert!(
        matches!(err, SourceError::Io(_)),
        "oversize stdin must map to SourceError::Io, got {err:?}"
    );
    assert_eq!(
        err.to_string(),
        format!(
            "failed to read source: stdin exceeds {limit} byte limit. Fix: check the path exists, is readable, and is not a broken symlink"
        )
    );
}

/// Spawn this test binary re-entrantly to run a single `#[ignore]`d child body
/// with `input` piped to its stdin and `envs` set, returning the child's exit
/// status. stdout/stderr are discarded so libtest's output can never fill a
/// pipe buffer and deadlock; the exit code is the sole oracle.
fn run_child(child_test: &str, input: &[u8], envs: &[(&str, &str)]) -> std::process::ExitStatus {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let exe = std::env::current_exe().expect("resolve current test binary path");
    let mut cmd = Command::new(exe);
    cmd.arg(child_test)
        .arg("--exact")
        .arg("--ignored")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (key, value) in envs {
        cmd.env(key, value);
    }

    let mut child = cmd.spawn().expect("spawn re-exec child test process");
    {
        let mut sink = child.stdin.take().expect("take child stdin handle");
        sink.write_all(input).expect("write bytes to child stdin");
    } // sink dropped here -> child sees EOF
    child.wait().expect("await child test process")
}

#[test]
fn piped_secret_yields_single_stdin_chunk() {
    let secret = "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n";
    let status = run_child(
        "stdin_child_default_source_single_chunk",
        secret.as_bytes(),
        &[("KEYHOG_TEST_STDIN_EXPECT", secret)],
    );
    assert_eq!(
        status.code(),
        Some(0),
        "child must confirm the piped secret becomes one stdin chunk with exact bytes + metadata"
    );
}

#[test]
fn empty_stdin_yields_exactly_one_empty_chunk() {
    // NOTE: the stdin source is built on `std::iter::once`, so empty stdin
    // yields ONE empty chunk, not zero. The child asserts `rows.len() == 1`
    // with empty `data`; an exit code of 0 confirms that exact behavior.
    let status = run_child(
        "stdin_child_default_source_single_chunk",
        b"",
        &[("KEYHOG_TEST_STDIN_EXPECT", "")],
    );
    assert_eq!(
        status.code(),
        Some(0),
        "empty stdin must still produce exactly one chunk carrying empty data"
    );
}

#[test]
fn multiline_pipe_chunk_keeps_base_line_zero() {
    // Whole-file (single-chunk) sources carry base_line 0 even for multi-line
    // input; the child asserts base_line == 0 alongside the exact bytes.
    let payload = "line1=a\nline2=token\nline3=c\n";
    let status = run_child(
        "stdin_child_default_source_single_chunk",
        payload.as_bytes(),
        &[("KEYHOG_TEST_STDIN_EXPECT", payload)],
    );
    assert_eq!(
        status.code(),
        Some(0),
        "multi-line piped stdin must be one chunk with base_line 0 and exact bytes"
    );
}

#[test]
fn binary_stdin_lossy_decoded_into_chunk() {
    // A lone 0xFF is invalid UTF-8; the chunk data must be the lossy decode
    // (U+FFFD) rather than a rejected source. Ties the public chunk path to the
    // documented lossy-decode contract.
    let status = run_child(
        "stdin_child_default_source_single_chunk",
        b"key=\xffval",
        &[("KEYHOG_TEST_STDIN_EXPECT", "key=\u{FFFD}val")],
    );
    assert_eq!(
        status.code(),
        Some(0),
        "invalid-UTF-8 stdin must be lossy-decoded inside the emitted chunk"
    );
}

#[test]
fn chunk_mismatch_surfaces_as_child_failure_exit_code() {
    // Negative twin: feeding bytes that do NOT match the expected value makes
    // the child's data assertion panic, so libtest exits 101. This also proves
    // the harness actually executes the child body (guarding the positive tests
    // from passing vacuously on a mistyped child name).
    let status = run_child(
        "stdin_child_default_source_single_chunk",
        b"hello-world",
        &[("KEYHOG_TEST_STDIN_EXPECT", "HELLO-WORLD")],
    );
    assert_eq!(
        status.code(),
        Some(101),
        "a chunk-bytes mismatch must fail the child test (libtest exit code 101)"
    );
}

#[test]
fn configured_over_limit_yields_error_chunk() {
    // Public builder path: 5 bytes against a 3-byte configured cap must yield
    // one SourceError::Io row with the exact message. The child performs the
    // assertions; exit 0 confirms them.
    let status = run_child(
        "stdin_child_configured_source_over_limit_errs",
        b"12345",
        &[("KEYHOG_TEST_STDIN_LIMIT", "3")],
    );
    assert_eq!(
        status.code(),
        Some(0),
        "oversized stdin through with_limits must surface one exact-message error row"
    );
}
