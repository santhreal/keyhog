//! Shared bounded stderr capture for child-process integrations.

use std::io::Read;

pub(crate) const STDERR_EXCERPT_BYTES: usize = 64 * 1024;
const STDERR_READ_BUFFER_BYTES: usize = 8192;

pub(crate) fn drain_stderr_excerpt(mut stderr_pipe: impl Read) -> String {
    let mut excerpt = Vec::new();
    let mut buffer = [0_u8; STDERR_READ_BUFFER_BYTES];
    let mut truncated = false;
    loop {
        match stderr_pipe.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                if excerpt.len() < STDERR_EXCERPT_BYTES {
                    let keep = read.min(STDERR_EXCERPT_BYTES - excerpt.len());
                    excerpt.extend_from_slice(&buffer[..keep]);
                    if keep < read {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Err(ref error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return format!("stderr unavailable: {error}"),
        }
    }

    let mut text = String::from_utf8_lossy(&excerpt).into_owned();
    if truncated {
        // NOTE: this literal byte count is pinned by the
        // `process_stderr_excerpt_owner` gate (tests/unit/gates/), which asserts
        // the owner file contains this exact marker string. It duplicates
        // `STDERR_EXCERPT_BYTES`'s value (a ONE-PLACE smell tracked in BACKLOG);
        // deriving it from the const requires updating that gate in the same
        // change, so keep the literal here until both move together.
        text.push_str("\n[stderr truncated after 65536 bytes]");
    }
    text
}

#[cfg(test)]
#[path = "../tests/unit/process_excerpt_inline.rs"]
mod tests;
