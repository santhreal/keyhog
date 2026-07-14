use super::{drain_stderr_excerpt, STDERR_EXCERPT_BYTES};
use std::io::{Error, ErrorKind, Read};

/// The truncation marker, derived from the cap const so these tests stay
/// correct if the cap changes, and so they lock the ONE-PLACE fix that made
/// the production marker derive the byte count from `STDERR_EXCERPT_BYTES`
/// instead of a hardcoded literal.
fn expected_marker() -> String {
    format!("\n[stderr truncated after {STDERR_EXCERPT_BYTES} bytes]")
}

#[test]
fn under_cap_returns_stderr_verbatim_without_marker() {
    let out = drain_stderr_excerpt(&b"child failed: bad flag\n"[..]);
    assert_eq!(out, "child failed: bad flag\n");
    assert!(
        !out.contains("truncated"),
        "a short stderr carries no truncation marker"
    );
}

#[test]
fn exactly_cap_is_kept_whole_without_truncation_marker() {
    let blob = vec![b'x'; STDERR_EXCERPT_BYTES];
    let out = drain_stderr_excerpt(&blob[..]);
    assert_eq!(
        out.len(),
        STDERR_EXCERPT_BYTES,
        "input of exactly the cap is kept whole"
    );
    assert!(
        !out.contains("truncated"),
        "exactly-cap input is complete, not truncated (boundary: keep == read on the last chunk)"
    );
}

#[test]
fn over_cap_keeps_the_first_64k_verbatim_and_appends_the_marker() {
    let blob = vec![b'y'; STDERR_EXCERPT_BYTES + 10_000];
    let out = drain_stderr_excerpt(&blob[..]);
    let marker = expected_marker();
    assert!(
        out.ends_with(&marker),
        "over-cap output ends with the truncation marker"
    );
    let body = &out[..out.len() - marker.len()];
    assert_eq!(
        body.len(),
        STDERR_EXCERPT_BYTES,
        "exactly the cap is kept before the marker"
    );
    assert!(
        body.bytes().all(|b| b == b'y'),
        "the kept prefix is the verbatim stderr head"
    );
}

#[test]
fn non_utf8_bytes_are_lossily_decoded_never_panic() {
    let out = drain_stderr_excerpt(&[0xFF, 0xFE, b'o', b'k', 0xFF][..]);
    assert!(
        out.contains('\u{FFFD}'),
        "invalid UTF-8 becomes the replacement char, no panic"
    );
    assert!(out.contains("ok"), "valid bytes survive the lossy decode");
}

/// Yields an `Interrupted` (EINTR) error once, then a data chunk, then EOF
/// proving the read loop RETRIES EINTR rather than aborting the capture.
struct InterruptOnceThenData {
    interrupted: bool,
    data: &'static [u8],
    done: bool,
}
impl Read for InterruptOnceThenData {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(Error::new(ErrorKind::Interrupted, "EINTR"));
        }
        if self.done {
            return Ok(0);
        }
        let n = self.data.len().min(buf.len());
        buf[..n].copy_from_slice(&self.data[..n]);
        self.done = true;
        Ok(n)
    }
}

#[test]
fn interrupted_reads_are_retried_not_aborted() {
    let reader = InterruptOnceThenData {
        interrupted: false,
        data: b"recovered stderr",
        done: false,
    };
    let out = drain_stderr_excerpt(reader);
    assert_eq!(
        out, "recovered stderr",
        "an EINTR is retried; the payload is still captured"
    );
}

struct HardErrorReader;
impl Read for HardErrorReader {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Err(Error::new(ErrorKind::BrokenPipe, "pipe died"))
    }
}

#[test]
fn a_hard_read_error_yields_an_unavailable_message() {
    let out = drain_stderr_excerpt(HardErrorReader);
    assert!(
        out.starts_with("stderr unavailable:"),
        "a non-EINTR read error surfaces as an unavailable message, got: {out}"
    );
    assert!(
        out.contains("pipe died"),
        "the underlying error is included for diagnosis"
    );
}
