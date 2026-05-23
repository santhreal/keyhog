pub(super) fn count_u64(count: usize, label: &str) -> u64 {
    u64::try_from(count).unwrap_or_else(|_| {
        panic!(
            "vyre-frontend-c security index {label} exceeds u64. Fix: shard the decoded object before building release-gate stats."
        )
    })
}
