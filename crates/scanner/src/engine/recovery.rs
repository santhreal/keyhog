use crate::hw_probe::ScanBackend;

const MAX_RECOVERY_REASON_BYTES: usize = 4096;
const MISSING_RECOVERY_REASON: &str = "backend fault without diagnostic";

/// One exact source-byte interval completed after the selected backend faulted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredInputRange {
    pub chunk_index: usize,
    pub byte_start: usize,
    pub byte_end: usize,
}

impl RecoveredInputRange {
    pub fn new(chunk_index: usize, byte_start: usize, byte_end: usize) -> Self {
        Self {
            chunk_index,
            byte_start,
            byte_end,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.byte_end.saturating_sub(self.byte_start)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.byte_start >= self.byte_end
    }
}

/// Complete, non-secret receipt for automatic recovery of stable input bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendRecoveryReceipt {
    pub failed_backend: ScanBackend,
    pub recovery_backend: ScanBackend,
    pub ranges: Vec<RecoveredInputRange>,
    pub reason: String,
}

impl BackendRecoveryReceipt {
    pub fn new(
        failed_backend: ScanBackend,
        recovery_backend: ScanBackend,
        ranges: Vec<RecoveredInputRange>,
        reason: String,
    ) -> Self {
        Self {
            failed_backend,
            recovery_backend,
            ranges: canonicalize_ranges(ranges),
            reason: sanitize_recovery_reason(reason),
        }
    }

    #[must_use]
    pub fn recovered_bytes(&self) -> u64 {
        self.ranges
            .iter()
            // LAW10: this is a diagnostic byte counter only; saturation cannot alter recovery candidates or findings.
            .map(|range| u64::try_from(range.len()).unwrap_or(u64::MAX))
            .fold(0u64, u64::saturating_add)
    }

    #[must_use]
    pub fn recovered_chunks(&self) -> usize {
        self.ranges
            .iter()
            .map(|range| range.chunk_index)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    }
}

fn sanitize_recovery_reason(reason: String) -> String {
    let mut sanitized = String::with_capacity(reason.len().min(MAX_RECOVERY_REASON_BYTES));
    for ch in reason.chars() {
        let ch = if ch.is_control() { '\u{fffd}' } else { ch };
        if sanitized.len().saturating_add(ch.len_utf8()) > MAX_RECOVERY_REASON_BYTES {
            break;
        }
        sanitized.push(ch);
    }
    if sanitized.is_empty() {
        MISSING_RECOVERY_REASON.to_string()
    } else {
        sanitized
    }
}

/// Result of one fallible coalesced dispatch, including any completed recovery.
pub struct CoalescedScanOutcome {
    pub matches: Vec<Vec<keyhog_core::RawMatch>>,
    pub recovery: Option<BackendRecoveryReceipt>,
}

// Tests live in `tests/unit/engine_recovery.rs` (KH-1308).

pub(crate) fn canonicalize_ranges(
    mut ranges: Vec<RecoveredInputRange>,
) -> Vec<RecoveredInputRange> {
    ranges.retain(|range| !range.is_empty());
    ranges.sort_unstable_by_key(|range| (range.chunk_index, range.byte_start, range.byte_end));
    let mut canonical: Vec<RecoveredInputRange> = Vec::with_capacity(ranges.len());
    for range in ranges {
        if let Some(last) = canonical.last_mut() {
            if last.chunk_index == range.chunk_index && range.byte_start <= last.byte_end {
                last.byte_end = last.byte_end.max(range.byte_end);
                continue;
            }
        }
        canonical.push(range);
    }
    canonical
}
