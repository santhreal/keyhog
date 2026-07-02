//! Regression coverage for the stdin source's **chunk-production** path
//! (`crates/sources/src/stdin.rs`).
//!
//! This file is the chunk-boundary / decode-boundary companion to
//! `regression_stdin_source.rs`. It targets truths that file does *not* pin:
//!
//! * the exact-cap vs one-over-cap byte boundary of `read_to_string_limited`
//!   (the pure decode helper, driven through the `Cursor`-backed test facade -
//!   no real process stdin, so it is deterministic);
//! * that the stdin *decode* layer is NOT the control-byte sanitizer (0x08 /
//!   0x0C survive here; sanitization happens later, on the scan path);
//! * lossy replacement of invalid / truncated UTF-8;
//! * the default `SourceLimits::stdin_bytes` constant the source resolves to;
//! * and, through a re-exec harness that pipes controlled bytes into a child
//!   copy of this binary, that a *large under-cap* payload stays exactly ONE
//!   chunk (stdin never splits on a boundary) with the whole-file metadata
//!   constants, that empty stdin still yields one empty chunk, and that an
//!   oversize configured cap yields exactly one wrapped `SourceError::Io` row.
//!
//! Every assertion is a concrete expected value: exact bytes, exact lengths,
//! exact error messages/kinds, exact metadata fields, exact skip-counter
//! deltas, exact child process exit codes.

use keyhog_core::{Source, SourceError};
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{SourceLimits, StdinSource};

// ---------------------------------------------------------------------------
// Pure decode-boundary truths (Cursor-backed facade; no real stdin).
// ---------------------------------------------------------------------------

#[test]
fn decode_at_exact_cap_boundary_returns_full() {
    // read_to_cap reads cap+1 and flags truncation only when len > cap. At
    // len == cap the input is exactly at the limit, NOT over, so it decodes
    // whole. Boundary twin of the one-over case below.
    let out = TestApi
        .read_stdin_test_input_with_limit(b"abcde", 5)
        .expect("5 bytes at a 5-byte cap is exactly at the limit, not over");
    assert_eq!(out, "abcde");
    assert_eq!(out.len(), 5);
}

#[test]
fn decode_one_byte_over_cap_fails_with_exact_message() {
    // len == cap + 1 is the first byte over the limit: a loud, counted failure
    // with the exact cap value in the message, never a silent truncation.
    let err = TestApi
        .read_stdin_test_input_with_limit(b"abcd", 3)
        .expect_err("4 bytes over a 3-byte cap must fail loud");
    assert_eq!(err.kind(), std::io::ErrorKind::Other);
    assert_eq!(err.to_string(), "stdin exceeds 3 byte limit");
}

#[test]
fn planted_secret_roundtrips_through_stdin_decode() {
    // A planted AWS secret must survive the decode byte-for-byte so the scanner
    // sees the exact value at the exact offset. `=` sits at index 21, the value
    // begins at index 22.
    let input = b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    let out = TestApi
        .read_stdin_test_input_with_limit(input, 1024)
        .expect("planted secret under the cap decodes verbatim");
    assert_eq!(out.len(), 62);
    assert_eq!(&out[..22], "AWS_SECRET_ACCESS_KEY=");
    assert_eq!(&out[22..], "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    assert_eq!(out.as_bytes()[21], b'=');
}

#[test]
fn backspace_and_formfeed_survive_stdin_decode_unsanitized() {
    // 0x08 (BS) and 0x0C (FF) are the non-whitespace control bytes the *scan*
    // path sanitizes. The stdin DECODE layer is not that sanitizer: both are
    // valid single-byte UTF-8 and must pass through here verbatim. This pins
    // where sanitization does and does not live.
    let out = TestApi
        .read_stdin_test_input_with_limit(b"a\x08b\x0cc", 1024)
        .expect("control bytes are valid UTF-8 and decode verbatim at the stdin layer");
    assert_eq!(out, "a\u{8}b\u{c}c");
    assert_eq!(out.len(), 5);
    assert_eq!(out.as_bytes()[1], 0x08);
    assert_eq!(out.as_bytes()[3], 0x0C);
}

#[test]
fn tab_byte_preserved_in_stdin_decode() {
    // 0x09 (TAB) is whitespace and must be preserved unconditionally.
    let out = TestApi
        .read_stdin_test_input_with_limit(b"k\tv", 1024)
        .expect("tab stdin under the cap decodes verbatim");
    assert_eq!(out, "k\tv");
    assert_eq!(out.len(), 3);
    assert_eq!(out.as_bytes()[1], 0x09);
}

#[test]
fn lone_continuation_byte_lossy_replaced() {
    // 0x80 is a bare UTF-8 continuation byte with no lead byte: invalid, so
    // from_utf8_lossy replaces it with a single U+FFFD (3 bytes) rather than
    // rejecting the whole stdin.
    let out = TestApi
        .read_stdin_test_input_with_limit(b"x\x80y", 1024)
        .expect("invalid UTF-8 is lossy-decoded, not rejected");
    assert_eq!(out, "x\u{FFFD}y");
    assert_eq!(out.chars().filter(|c| *c == '\u{FFFD}').count(), 1);
    assert_eq!(out.len(), 5); // 'x' + 3-byte U+FFFD + 'y'
}

#[test]
fn truncated_multibyte_tail_lossy_replaced() {
    // A 3-byte euro sign (E2 82 AC) cut to its first two bytes is an incomplete
    // sequence at EOF; lossy decode emits one U+FFFD for the dangling prefix.
    let out = TestApi
        .read_stdin_test_input_with_limit(b"pay=\xe2\x82", 1024)
        .expect("truncated multibyte tail is lossy-decoded");
    assert_eq!(out, "pay=\u{FFFD}");
    assert_eq!(out.chars().filter(|c| *c == '\u{FFFD}').count(), 1);
    assert_eq!(out.len(), 7); // "pay=" (4) + 3-byte U+FFFD
}

#[test]
fn cap_far_above_input_returns_whole_payload() {
    // A tiny input under a huge cap returns whole: the cap only bounds oversize
    // stdin, it never pads or trims a compliant read.
    let out = TestApi
        .read_stdin_test_input_with_limit(b"token=abc", 10 * 1024 * 1024)
        .expect("a small payload under a 10 MiB cap decodes whole");
    assert_eq!(out, "token=abc");
    assert_eq!(out.len(), 9);
}

#[test]
fn over_cap_increments_over_max_size_once_under_guard() {
    // The over-cap failure is a loud, counted skip (Law 10): exactly one
    // OverMaxSize increment, and an in-cap read leaves the counter at zero.
    // Held under an exclusive scan scope so the process-global counter is not
    // polluted by concurrent gated scans.
    let _guard = TestApi.skip_counter_guard();

    TestApi.reset_skip_counters();
    let err = TestApi
        .read_stdin_test_input_with_limit(b"eleven_byte", 10)
        .expect_err("11 bytes over a 10-byte cap must fail loud");
    assert_eq!(err.to_string(), "stdin exceeds 10 byte limit");
    assert_eq!(keyhog_sources::skip_counts().over_max_size, 1);

    TestApi.reset_skip_counters();
    let ok = TestApi
        .read_stdin_test_input_with_limit(b"under", 10)
        .expect("5 bytes under a 10-byte cap must succeed");
    assert_eq!(ok, "under");
    assert_eq!(keyhog_sources::skip_counts().over_max_size, 0);
}

#[test]
fn default_stdin_cap_is_ten_mib_and_empty_decodes_empty() {
    // The stdin source resolves its cap from SourceLimits::stdin_bytes; pin the
    // exact default (10 MiB) the plain `StdinSource` uses, and prove empty input
    // at that cap is the empty string (len 0 is at the limit, never over).
    let cap = SourceLimits::default().stdin_bytes;
    assert_eq!(cap, 10 * 1024 * 1024);
    assert_eq!(cap, 10_485_760);

    let out = TestApi
        .read_stdin_test_input_with_limit(b"", cap)
        .expect("empty stdin at the default cap decodes to the empty string");
    assert_eq!(out, "");
    assert_eq!(out.len(), 0);
}

// ---------------------------------------------------------------------------
// Public `Source::chunks()` chunk-level contract, via a controlled stdin pipe.
//
// The `#[ignore]`d child bodies below read the real process stdin and are only
// ever launched by the parent tests (which pipe controlled bytes + set envs).
// They never run during a normal `cargo test` and so never block on a TTY.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "harness child: launched by a parent test with a controlled stdin pipe; reads real process stdin"]
fn stdin_chunk_metadata_child() {
    // Assert the full emitted chunk: exact bytes (== KEYHOG_TEST_STDIN_EXPECT),
    // the "stdin" source label, and every whole-file metadata constant.
    let expected = std::env::var("KEYHOG_TEST_STDIN_EXPECT").unwrap_or_default();

    let rows: Vec<_> = StdinSource.chunks().collect();
    assert_eq!(rows.len(), 1, "stdin must emit exactly one chunk row");

    let chunk = match rows.into_iter().next().unwrap() {
        Ok(chunk) => chunk,
        Err(err) => panic!("stdin chunk must be Ok, got {err:?}"),
    };

    assert_eq!(&*chunk.data, expected.as_str());
    assert_eq!(chunk.data.len(), expected.len());
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
#[ignore = "harness child: launched by a parent test that pipes a large under-cap payload"]
fn stdin_large_chunk_child() {
    // A large payload well under the cap must stay exactly ONE chunk: stdin is
    // built on `std::iter::once`, so it never splits on a size boundary the way
    // the windowed filesystem source does.
    let len: usize = std::env::var("KEYHOG_TEST_STDIN_LEN")
        .expect("KEYHOG_TEST_STDIN_LEN must be set by the parent")
        .parse()
        .expect("KEYHOG_TEST_STDIN_LEN must parse as usize");

    let rows: Vec<_> = StdinSource.chunks().collect();
    assert_eq!(
        rows.len(),
        1,
        "a large under-cap payload must be one chunk, not many"
    );

    let chunk = match rows.into_iter().next().unwrap() {
        Ok(chunk) => chunk,
        Err(err) => panic!("large stdin chunk must be Ok, got {err:?}"),
    };
    assert_eq!(chunk.data.len(), len);
    assert_eq!(chunk.metadata.source_type, "stdin");
    assert_eq!(chunk.metadata.base_offset, 0);
    assert!(chunk.data.as_bytes().iter().all(|b| *b == b'A'));
}

#[test]
#[ignore = "harness child: launched by a parent test that pipes oversized stdin against a tiny configured cap"]
fn stdin_over_limit_chunk_child() {
    // The public builder path (`with_limits`) must surface an oversize stdin as
    // exactly one wrapped `SourceError::Io` row with the exact byte-limit
    // message, never a silent truncation.
    let limit: usize = std::env::var("KEYHOG_TEST_STDIN_LIMIT")
        .expect("KEYHOG_TEST_STDIN_LIMIT must be set by the parent")
        .parse()
        .expect("KEYHOG_TEST_STDIN_LIMIT must parse as usize");

    let limits = SourceLimits {
        stdin_bytes: limit,
        ..SourceLimits::default()
    };

    let rows: Vec<_> = StdinSource.with_limits(limits).chunks().collect();
    assert_eq!(rows.len(), 1, "even the error path emits exactly one row");

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

/// Re-exec this test binary to run one `#[ignore]`d child body with `input`
/// piped to its stdin and `envs` set, returning the child's exit status.
/// stdout/stderr are discarded so libtest output cannot fill a pipe and
/// deadlock; the exit code is the sole oracle (0 = child asserts passed,
/// 101 = a child assertion panicked).
fn run_stdin_child(child: &str, input: &[u8], envs: &[(&str, &str)]) -> std::process::ExitStatus {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let exe = std::env::current_exe().expect("resolve current test binary path");
    let mut cmd = Command::new(exe);
    cmd.arg(child)
        .arg("--exact")
        .arg("--ignored")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (key, value) in envs {
        cmd.env(key, value);
    }

    let mut proc = cmd.spawn().expect("spawn re-exec child test process");
    {
        let mut sink = proc.stdin.take().expect("take child stdin handle");
        sink.write_all(input).expect("write bytes to child stdin");
    } // sink dropped -> child sees EOF
    proc.wait().expect("await child test process")
}

#[test]
fn piped_secret_becomes_single_stdin_chunk_with_exact_metadata() {
    let secret = "github_token=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\n";
    let status = run_stdin_child(
        "stdin_chunk_metadata_child",
        secret.as_bytes(),
        &[("KEYHOG_TEST_STDIN_EXPECT", secret)],
    );
    assert_eq!(
        status.code(),
        Some(0),
        "the piped secret must become one stdin chunk with exact bytes + whole-file metadata"
    );
}

#[test]
fn empty_pipe_yields_one_empty_stdin_chunk() {
    // std::iter::once => empty stdin is ONE empty chunk, not zero rows.
    let status = run_stdin_child(
        "stdin_chunk_metadata_child",
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
fn large_under_cap_payload_stays_single_chunk() {
    // 256 KiB (>> the 64 KiB preallocation ceiling, << the 10 MiB cap) must
    // arrive as ONE chunk: proof stdin never splits on a size boundary.
    let payload = vec![b'A'; 262_144];
    let status = run_stdin_child(
        "stdin_large_chunk_child",
        &payload,
        &[("KEYHOG_TEST_STDIN_LEN", "262144")],
    );
    assert_eq!(
        status.code(),
        Some(0),
        "a 256 KiB under-cap payload must be exactly one stdin chunk"
    );
}

#[test]
fn configured_over_cap_yields_single_error_row() {
    // 10 bytes against a 7-byte configured cap => one wrapped SourceError::Io.
    let status = run_stdin_child(
        "stdin_over_limit_chunk_child",
        b"0123456789",
        &[("KEYHOG_TEST_STDIN_LIMIT", "7")],
    );
    assert_eq!(
        status.code(),
        Some(0),
        "oversize stdin through with_limits must surface one exact-message error row"
    );
}

#[test]
fn mismatched_bytes_fail_child_with_exit_code_101() {
    // Negative twin + harness self-check: feeding bytes that do NOT match the
    // expected value makes the child's data assertion panic (libtest exit 101),
    // proving the child body actually executes and the positive tests are not
    // passing vacuously.
    let status = run_stdin_child(
        "stdin_chunk_metadata_child",
        b"actual-bytes",
        &[("KEYHOG_TEST_STDIN_EXPECT", "different-bytes")],
    );
    assert_eq!(
        status.code(),
        Some(101),
        "a chunk-bytes mismatch must fail the child test with libtest exit code 101"
    );
}
