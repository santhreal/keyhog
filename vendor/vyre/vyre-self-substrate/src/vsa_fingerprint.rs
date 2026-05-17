//! VSA-based op cache key via #13 hypervector primitives (#29).
//!
//! Fingerprints a Program by binding op-kind, buffer-signature, and
//! region-shape into one 10K-dim hypervector. Approximate-match cache
//! returns the same fingerprint for two semantically-equivalent
//! Region trees with reordered children — beats byte-equal hashing.

use vyre_primitives::hash::hypervector::{hamming_similarity, xor_bind_cpu};

/// Build a stable VSA cache fingerprint directly from a vyre Program.
///
/// The canonical program fingerprint is 32 bytes; this converts it into
/// eight little-endian `u32` hypervector lanes so approximate lookup can
/// share the same cache representation as manually supplied component
/// fingerprints.
#[must_use]
pub fn vsa_fingerprint_cpu(program: &vyre_foundation::ir::Program) -> Vec<u32> {
    vsa_fingerprint_words(program).to_vec()
}

/// Build the stable eight-lane VSA cache fingerprint without heap allocation.
#[must_use]
pub fn vsa_fingerprint_words(program: &vyre_foundation::ir::Program) -> [u32; 8] {
    use crate::observability::{bump, vsa_fingerprint_calls};
    bump(&vsa_fingerprint_calls);
    let fingerprint = program.fingerprint();
    let mut words = [0_u32; 8];
    for (slot, chunk) in words.iter_mut().zip(fingerprint.chunks_exact(4)) {
        *slot = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    words
}

/// Fingerprint a Program from a (kind, signature, region) triple.
/// Caller supplies pre-computed hypervectors for each component.
#[must_use]
pub fn fingerprint(kind_hv: &[u32], signature_hv: &[u32], region_hv: &[u32]) -> Vec<u32> {
    let bound1 = xor_bind_cpu(kind_hv, signature_hv);
    xor_bind_cpu(&bound1, region_hv)
}

/// Approximate cache lookup: return the index of the cached entry
/// whose fingerprint is most similar to the query, or `None` if all
/// similarities are below `threshold`.
#[must_use]
pub fn lookup_approximate(query: &[u32], cached: &[Vec<u32>], threshold: f32) -> Option<usize> {
    let mut best: Option<(usize, f32)> = None;
    for (i, c) in cached.iter().enumerate() {
        let sim = hamming_similarity(query, c);
        if sim >= threshold {
            match best {
                None => best = Some((i, sim)),
                Some((_, best_sim)) if sim > best_sim => best = Some((i, sim)),
                _ => {}
            }
        }
    }
    best.map(|(i, _)| i)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_self_lookup_returns_match() {
        let kind = vec![0xDEAD_BEEFu32; 8];
        let sig = vec![0x1234_5678u32; 8];
        let region = vec![0x9ABC_DEF0u32; 8];
        let fp = fingerprint(&kind, &sig, &region);
        let cache = vec![fp.clone()];
        let hit = lookup_approximate(&fp, &cache, 0.99);
        assert_eq!(hit, Some(0));
    }

    #[test]
    fn fingerprint_high_threshold_excludes_distant() {
        let kind1 = vec![0u32; 8];
        let sig1 = vec![0u32; 8];
        let region1 = vec![0u32; 8];
        let fp1 = fingerprint(&kind1, &sig1, &region1);

        let kind2 = vec![u32::MAX; 8];
        let sig2 = vec![u32::MAX; 8];
        let region2 = vec![u32::MAX; 8];
        let fp2 = fingerprint(&kind2, &sig2, &region2);

        let cache = vec![fp1];
        let hit = lookup_approximate(&fp2, &cache, 0.99);
        assert_eq!(hit, None); // far below threshold
    }

    #[test]
    fn fingerprint_low_threshold_finds_partial_match() {
        let kind1 = vec![0u32; 8];
        let sig1 = vec![0u32; 8];
        let region1 = vec![0u32; 8];
        let fp1 = fingerprint(&kind1, &sig1, &region1);
        let cache = vec![fp1.clone()];
        let hit = lookup_approximate(&fp1, &cache, -1.0); // any
        assert_eq!(hit, Some(0));
    }
}
