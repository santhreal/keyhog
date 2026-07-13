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

/// Upper bound on the initial `Vec` reservation for a capped read.
///
/// `read_to_cap*` clamps its preallocation to this ceiling so a hostile
/// capacity hint cannot force a giant up-front allocation (see the
/// decompression-bomb tests below). Cloud/web/hosted-git callers that compute a
/// capacity hint for `read_to_cap` clamp to the SAME ceiling, so this is the
/// single owner of that 64 KiB value, they reference it instead of pasting
/// `64 * 1024` inline.
pub(crate) const MAX_PREALLOCATED_READ_BYTES: u64 = 64 * 1024;

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
    let read_limit = cap.checked_add(1).unwrap_or(u64::MAX); // LAW10: recall-preserving (u64::MAX has no representable sentinel byte; reading up to the finite reader cap still reads all reachable bytes).
    let cap_usize = usize::try_from(cap).unwrap_or(usize::MAX); // LAW10: unreachable on real platforms (a Vec length cannot exceed usize::MAX, so larger caps cannot be crossed by an in-memory read result).
    let max_addressable_capacity = u64::try_from(usize::MAX).unwrap_or(u64::MAX); // LAW10: unreachable on real platforms (only a wider-than-u64 usize target takes this arm, where every u64 capacity hint is addressable).
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
#[path = "../tests/unit/capped_read.rs"]
mod tests;
