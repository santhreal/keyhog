use std::io::{self, Read};

pub(crate) struct CappedRead {
    pub(crate) bytes: Vec<u8>,
    pub(crate) truncated: bool,
}

pub(crate) fn read_to_cap(
    reader: impl Read,
    cap: u64,
    capacity_hint: Option<u64>,
    label: &str,
) -> io::Result<CappedRead> {
    let read_limit = cap.checked_add(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} cap cannot represent the truncation sentinel byte"),
        )
    })?;
    let cap_usize = usize::try_from(cap).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} cap is too large for this platform"),
        )
    })?;
    let capacity = capacity_hint
        .unwrap_or(0) // LAW10: absent capacity hint only disables Vec preallocation; read_limit still enforces the byte cap
        .min(read_limit)
        .try_into()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{label} capped read capacity exceeds this platform's addressable memory"),
            )
        })?;

    let mut bytes = Vec::with_capacity(capacity);
    reader.take(read_limit).read_to_end(&mut bytes)?;
    let truncated = bytes.len() > cap_usize;
    if truncated {
        bytes.truncate(cap_usize);
    }
    Ok(CappedRead { bytes, truncated })
}
