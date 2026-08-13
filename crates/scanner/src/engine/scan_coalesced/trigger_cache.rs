//! Reusable SIMD trigger evidence for scan coalescing.

#[cfg(feature = "simd")]
use std::sync::Arc;

#[cfg(feature = "simd")]
const REUSABLE_SIMD_TRIGGER_MAX_BYTES: usize = 1024 * 1024;
#[cfg(feature = "simd")]
const REUSABLE_SIMD_TRIGGER_MAX_ENTRIES: usize = 16;

#[cfg(feature = "simd")]
struct ReusableSimdTriggerEntry {
    fingerprint: [u8; 32],
    payload_hash: [u8; 32],
    payload_len: usize,
    triggers: Option<Arc<[u64]>>,
}

#[cfg(feature = "simd")]
impl ReusableSimdTriggerEntry {
    fn resident_bytes(&self) -> usize {
        std::mem::size_of::<Self>().saturating_add(self.triggers.as_ref().map_or(0, |row| {
            row.len().saturating_mul(std::mem::size_of::<u64>())
        }))
    }
}

#[cfg(feature = "simd")]
#[derive(Default)]
pub(crate) struct ReusableSimdTriggerCache {
    entries: std::collections::VecDeque<ReusableSimdTriggerEntry>,
    resident_bytes: usize,
    #[cfg(debug_assertions)]
    hits: u64,
}

#[cfg(feature = "simd")]
impl ReusableSimdTriggerCache {
    fn payload_identity(payload: &keyhog_core::SensitiveString) -> ([u8; 32], [u8; 32], usize) {
        (
            super::phase1_admission::phase1_payload_fingerprint(payload.as_bytes()),
            *blake3::hash(payload.as_bytes()).as_bytes(),
            payload.len(),
        )
    }

    fn get_with_identity(
        &mut self,
        fingerprint: [u8; 32],
        payload_hash: [u8; 32],
        payload_len: usize,
    ) -> Option<Option<Arc<[u64]>>> {
        let position = self.entries.iter().position(|entry| {
            entry.fingerprint == fingerprint
                && entry.payload_len == payload_len
                && entry.payload_hash == payload_hash
        })?;
        let entry = self.entries.remove(position)?;
        let triggers = entry.triggers.clone();
        self.entries.push_back(entry);
        #[cfg(debug_assertions)]
        {
            self.hits = self.hits.saturating_add(1);
        }
        Some(triggers)
    }

    pub(crate) fn get(
        &mut self,
        payload: &keyhog_core::SensitiveString,
    ) -> Option<Option<Arc<[u64]>>> {
        let (fingerprint, payload_hash, payload_len) = Self::payload_identity(payload);
        self.get_with_identity(fingerprint, payload_hash, payload_len)
    }

    pub(crate) fn get_or_compute(
        &mut self,
        payload: &keyhog_core::SensitiveString,
        compute: impl FnOnce() -> Result<Option<Vec<u64>>, String>,
    ) -> Result<Option<Arc<[u64]>>, String> {
        let (fingerprint, payload_hash, payload_len) = Self::payload_identity(payload);
        if let Some(triggers) = self.get_with_identity(fingerprint, payload_hash, payload_len) {
            return Ok(triggers);
        }

        let computed_triggers: Option<Arc<[u64]>> = compute()?.map(Into::into);
        let entry = ReusableSimdTriggerEntry {
            fingerprint,
            payload_hash,
            payload_len,
            triggers: computed_triggers.clone(),
        };
        let resident_bytes = entry.resident_bytes();
        if resident_bytes > REUSABLE_SIMD_TRIGGER_MAX_BYTES {
            return Ok(computed_triggers);
        }
        while self.entries.len() >= REUSABLE_SIMD_TRIGGER_MAX_ENTRIES
            || self.resident_bytes.saturating_add(resident_bytes) > REUSABLE_SIMD_TRIGGER_MAX_BYTES
        {
            let Some(evicted) = self.entries.pop_front() else {
                break;
            };
            self.resident_bytes = self.resident_bytes.saturating_sub(evicted.resident_bytes());
        }
        self.resident_bytes = self.resident_bytes.saturating_add(resident_bytes);
        self.entries.push_back(entry);
        Ok(computed_triggers)
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
        self.resident_bytes = 0;
    }

    pub(crate) fn contains_payload_bytes(&self) -> bool {
        // LAW10: ReusableSimdTriggerEntry stores only 32-byte hashes, lengths, and trigger bitsets; payload bytes are never stored, so this query has no runtime effect.
        self.entries.iter().any(|_entry| false)
    }

    #[cfg(debug_assertions)]
    pub(crate) fn reset_hits(&mut self) {
        self.hits = 0;
    }

    #[cfg(debug_assertions)]
    pub(crate) fn hits(&self) -> u64 {
        self.hits
    }
}

#[cfg(feature = "simd")]
#[inline]
pub(crate) fn mark_hs_trigger(
    scratch: &mut [u64],
    prefilter: &super::SimdPhase1Prefilter,
    ac_len: usize,
    hs_id: usize,
) {
    if let Some(orig) = prefilter.original_indices(hs_id) {
        for &idx in orig {
            let idx = idx as usize;
            if idx < ac_len {
                scratch[idx / 64] |= 1u64 << (idx % 64);
            }
        }
    }
}
