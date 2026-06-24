use std::io::{self, Read};

pub(crate) struct CappedRead {
    pub(crate) bytes: Vec<u8>,
    pub(crate) truncated: bool,
}

pub(crate) fn read_to_cap(
    reader: impl Read,
    cap: u64,
    capacity_hint: Option<u64>,
) -> io::Result<CappedRead> {
    let read_limit = cap.checked_add(1).unwrap_or(u64::MAX); // LAW10: u64::MAX has no representable sentinel byte; reading up to the finite reader cap preserves all reachable bytes.
    let cap_usize = usize::try_from(cap).unwrap_or(usize::MAX); // LAW10: a Vec length cannot exceed usize::MAX on this platform, so larger caps cannot be crossed by an in-memory read result.
    let max_addressable_capacity = u64::try_from(usize::MAX).unwrap_or(u64::MAX); // LAW10: on wider-than-u64 usize targets, every u64 capacity hint is addressable.
    let capacity = capacity_hint
        .unwrap_or(0) // LAW10: absent capacity hint only disables Vec preallocation; read_limit still enforces the byte cap
        .min(read_limit)
        .min(max_addressable_capacity) as usize;

    let mut bytes = Vec::with_capacity(capacity);
    reader.take(read_limit).read_to_end(&mut bytes)?;
    let truncated = bytes.len() > cap_usize;
    if truncated {
        bytes.truncate(cap_usize);
    }
    Ok(CappedRead { bytes, truncated })
}

#[cfg(test)]
mod tests {
    use super::read_to_cap;

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
}
