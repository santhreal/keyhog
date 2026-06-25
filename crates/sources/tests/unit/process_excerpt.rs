use keyhog_sources::testing::{SourceTestApi, TestApi};
use std::io::{Error, ErrorKind, Read};

struct InterruptedThenBytes {
    interrupted: bool,
    bytes: &'static [u8],
}

impl Read for InterruptedThenBytes {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(Error::new(ErrorKind::Interrupted, "signal"));
        }
        let read = self.bytes.len().min(buf.len());
        buf[..read].copy_from_slice(&self.bytes[..read]);
        self.bytes = &self.bytes[read..];
        Ok(read)
    }
}

#[test]
fn stderr_excerpt_retries_interrupted_reads() {
    let mut reader = InterruptedThenBytes {
        interrupted: false,
        bytes: b"real stderr after signal",
    };

    let excerpt = TestApi.drain_process_stderr_excerpt(&mut reader);

    assert_eq!(excerpt, "real stderr after signal");
}
