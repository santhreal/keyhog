use std::io::{self, Read};

pub(crate) struct CappedRead {
    pub(crate) bytes: Vec<u8>,
    pub(crate) truncated: bool,
}

pub(crate) struct CappedReadPrefix {
    pub(crate) bytes: Vec<u8>,
    pub(crate) truncated: bool,
    pub(crate) error: Option<io::Error>,
}

const MAX_PREALLOCATED_READ_BYTES: u64 = 64 * 1024;

pub(crate) fn read_to_cap(
    reader: impl Read,
    cap: u64,
    capacity_hint: Option<u64>,
) -> io::Result<CappedRead> {
    let read = read_to_cap_preserving_error(reader, cap, capacity_hint);
    if let Some(error) = read.error {
        return Err(error);
    }
    Ok(CappedRead {
        bytes: read.bytes,
        truncated: read.truncated,
    })
}

pub(crate) fn read_to_cap_preserving_error(
    reader: impl Read,
    cap: u64,
    capacity_hint: Option<u64>,
) -> CappedReadPrefix {
    let read_limit = cap.checked_add(1).unwrap_or(u64::MAX); // LAW10: recall-preserving — u64::MAX has no representable sentinel byte; reading up to the finite reader cap still reads all reachable bytes.
    let cap_usize = usize::try_from(cap).unwrap_or(usize::MAX); // LAW10: unreachable on real platforms — a Vec length cannot exceed usize::MAX, so larger caps cannot be crossed by an in-memory read result.
    let max_addressable_capacity = u64::try_from(usize::MAX).unwrap_or(u64::MAX); // LAW10: unreachable on real platforms — only a wider-than-u64 usize target takes this arm, where every u64 capacity hint is addressable.
    let capacity = capacity_hint
        .unwrap_or(0) // LAW10: absent capacity hint only disables Vec preallocation; read_limit still enforces the byte cap
        .min(read_limit)
        .min(max_addressable_capacity)
        .min(MAX_PREALLOCATED_READ_BYTES) as usize;

    let mut bytes = Vec::with_capacity(capacity);
    let error = reader.take(read_limit).read_to_end(&mut bytes).err();
    let truncated = bytes.len() > cap_usize;
    if truncated {
        bytes.truncate(cap_usize);
    }
    CappedReadPrefix {
        bytes,
        truncated,
        error,
    }
}

#[cfg(test)]
mod tests {
    use super::{read_to_cap, read_to_cap_preserving_error};
    use std::io::{Error, ErrorKind, Read};

    struct FailsAfterPrefix {
        bytes: &'static [u8],
        emitted: bool,
    }

    impl Read for FailsAfterPrefix {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.emitted {
                return Err(Error::new(ErrorKind::InvalidData, "decode failed"));
            }
            let len = self.bytes.len().min(buf.len());
            buf[..len].copy_from_slice(&self.bytes[..len]);
            self.emitted = true;
            Ok(len)
        }
    }

    #[test]
    fn read_to_cap_keeps_exact_cap_without_truncation() {
        let read = read_to_cap(&b"abcd"[..], 4, Some(4)).expect("read");

        assert_eq!(read.bytes, b"abcd");
        assert!(!read.truncated);
    }

    #[test]
    fn read_to_cap_truncates_one_byte_over_cap() {
        let read = read_to_cap(&b"abcde"[..], 4, Some(5)).expect("read");

        assert_eq!(read.bytes, b"abcd");
        assert!(read.truncated);
    }

    #[test]
    fn read_to_cap_accepts_u64_max_without_sentinel_overflow() {
        let read = read_to_cap(&b"abc"[..], u64::MAX, Some(3)).expect("read");

        assert_eq!(read.bytes, b"abc");
        assert!(!read.truncated);
    }

    #[test]
    fn read_to_cap_clamps_capacity_hint_above_platform_capacity() {
        let read = read_to_cap(&b"abc"[..], 3, Some(u64::MAX)).expect("read");

        assert_eq!(read.bytes, b"abc");
        assert!(!read.truncated);
    }

    #[test]
    fn read_to_cap_clamps_unlimited_cap_and_huge_capacity_hint() {
        let read = read_to_cap(std::io::empty(), u64::MAX, Some(u64::MAX)).expect("read");

        assert!(read.bytes.is_empty());
        assert!(read.bytes.capacity() <= super::MAX_PREALLOCATED_READ_BYTES as usize);
        assert!(!read.truncated);
    }

    #[test]
    fn read_to_cap_preserving_error_keeps_partial_prefix() {
        let read = read_to_cap_preserving_error(
            FailsAfterPrefix {
                bytes: b"prefix",
                emitted: false,
            },
            10,
            Some(6),
        );

        assert_eq!(read.bytes, b"prefix");
        assert!(!read.truncated);
        assert_eq!(read.error.expect("error").kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn read_to_cap_preserving_error_truncates_to_cap() {
        let read = read_to_cap_preserving_error(&b"abcdef"[..], 4, Some(6));

        assert_eq!(read.bytes, b"abcd");
        assert!(read.truncated);
        assert!(read.error.is_none());
    }
}
