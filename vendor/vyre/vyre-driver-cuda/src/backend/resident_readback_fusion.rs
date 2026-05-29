//! CUDA-facing resident D2H readback interval fusion adapter.
//!
//! The interval coalescing policy is backend-neutral. This module preserves the
//! CUDA domain names used by resident IO/dispatch while delegating the actual
//! fusion algorithm to `vyre-driver`.

use vyre_driver::resident_transfer_fusion::{
    fuse_resident_transfer_intervals, FusedResidentTransfers, ResidentTransferInterval,
    ResidentTransferView,
};
use vyre_driver::BackendError;

/// One validated device-to-host readback request.
pub(crate) type ResidentReadbackCopy = ResidentTransferInterval;

/// How an original requested output is sliced out of a fused transfer.
pub(crate) type ResidentReadbackView = ResidentTransferView;

/// Fused transfer plan plus original-output views.
pub(crate) type FusedResidentReadbacks = FusedResidentTransfers;

/// Fuse overlapping or adjacent readback intervals, scoped by resident handle.
pub(crate) fn fuse_resident_readback_copies(
    requested: &[ResidentReadbackCopy],
) -> Result<FusedResidentReadbacks, BackendError> {
    fuse_resident_transfer_intervals(requested)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{fuse_resident_readback_copies, ResidentReadbackCopy};

    #[test]
    fn generated_fusion_preserves_every_requested_output_and_accounts_union_bytes() {
        for seed in 0..8192_u64 {
            let requested = generated_requests(seed);
            let fused = fuse_resident_readback_copies(&requested)
                .expect("Fix: generated resident readback requests must fuse without overflow");

            assert_eq!(
                fused.views.len(),
                requested.len(),
                "Fix: fused views must preserve request cardinality for seed {seed}."
            );
            assert_eq!(
                fused.non_empty_copy_count,
                fused.copies.len(),
                "Fix: fused copy count must match non-empty copy slots for seed {seed}."
            );
            assert_eq!(
                fused.bytes,
                expected_union_bytes(&requested),
                "Fix: fused byte accounting must equal the handle-scoped interval union for seed {seed}."
            );

            for pair in fused.copies.windows(2) {
                let left = pair[0];
                let right = pair[1];
                let left_end = left.src + left.byte_len as u64;
                assert!(
                    left.handle_id != right.handle_id || right.src > left_end,
                    "Fix: fused copies must not leave mergeable same-handle intervals for seed {seed}."
                );
            }

            for (index, request) in requested.iter().enumerate() {
                let view = fused.views[index];
                assert_eq!(
                    view.byte_len, request.byte_len,
                    "Fix: fused view length must preserve request {index} for seed {seed}."
                );
                if request.byte_len == 0 {
                    assert_eq!(
                        materialize_view(&fused.copies, view.copy_slot, view.byte_offset, view.byte_len),
                        Vec::<u8>::new(),
                        "Fix: zero-byte request {index} must materialize empty output for seed {seed}."
                    );
                } else {
                    assert!(
                        view.copy_slot < fused.copies.len(),
                        "Fix: non-empty request {index} must map to a real fused copy for seed {seed}."
                    );
                    assert_eq!(
                        fused.copies[view.copy_slot].handle_id, request.handle_id,
                        "Fix: request {index} must not read bytes from a different resident handle for seed {seed}."
                    );
                    assert_eq!(
                        materialize_view(
                            &fused.copies,
                            view.copy_slot,
                            view.byte_offset,
                            view.byte_len
                        ),
                        materialize_request(*request),
                        "Fix: fused view must reproduce request {index} byte-for-byte for seed {seed}."
                    );
                }
            }
        }
    }

    #[test]
    fn monotonic_resident_readbacks_fuse_without_reordering_views() {
        let requested = [
            ResidentReadbackCopy {
                handle_id: 1,
                src: 100,
                byte_len: 8,
            },
            ResidentReadbackCopy {
                handle_id: 1,
                src: 104,
                byte_len: 4,
            },
            ResidentReadbackCopy {
                handle_id: 2,
                src: 16,
                byte_len: 2,
            },
        ];

        let fused = fuse_resident_readback_copies(&requested)
            .expect("Fix: monotonic resident readback fusion must not require sorting.");

        assert_eq!(
            fused.copies.len(),
            2,
            "Fix: monotonic same-handle intervals must still fuse on the sorted fast path."
        );
        assert_eq!(fused.copies[0].handle_id, 1);
        assert_eq!(fused.copies[0].src, 100);
        assert_eq!(fused.copies[0].byte_len, 8);
        assert_eq!(fused.copies[1].handle_id, 2);
        assert_eq!(
            fused.views[0].copy_slot, 0,
            "Fix: first monotonic request must map to the first fused copy."
        );
        assert_eq!(
            fused.views[1].byte_offset, 4,
            "Fix: overlapping monotonic request must retain its offset inside the fused copy."
        );
        assert_eq!(
            fused.views[2].copy_slot, 1,
            "Fix: monotonic distinct-handle request must map to its own fused copy."
        );
    }

    #[test]
    fn adjacent_raw_pointers_from_distinct_handles_do_not_fuse() {
        let requested = [
            ResidentReadbackCopy {
                handle_id: 1,
                src: 100,
                byte_len: 8,
            },
            ResidentReadbackCopy {
                handle_id: 2,
                src: 108,
                byte_len: 8,
            },
        ];

        let fused = fuse_resident_readback_copies(&requested)
            .expect("Fix: distinct-handle adjacent ranges must fuse-check without error");

        assert_eq!(
            fused.copies.len(),
            2,
            "Fix: adjacent raw pointers from distinct resident allocations must not coalesce."
        );
        assert_eq!(fused.bytes, 16);
    }

    fn generated_requests(seed: u64) -> Vec<ResidentReadbackCopy> {
        let mut state = seed ^ 0xC0DA_CAFE_51DE_D2D2;
        let count = 1 + (next_u64(&mut state) as usize % 16);
        let mut requests = Vec::with_capacity(count);
        for _ in 0..count {
            let handle_id = next_u64(&mut state) % 4;
            let src = next_u64(&mut state) % 64;
            let byte_len = next_u64(&mut state) as usize % 17;
            requests.push(ResidentReadbackCopy {
                handle_id,
                src,
                byte_len,
            });
        }
        requests
    }

    fn expected_union_bytes(requests: &[ResidentReadbackCopy]) -> u64 {
        let mut bytes = HashSet::<(u64, u64)>::new();
        for request in requests {
            for offset in 0..request.byte_len as u64 {
                bytes.insert((request.handle_id, request.src + offset));
            }
        }
        bytes.len() as u64
    }

    fn materialize_view(
        copies: &[ResidentReadbackCopy],
        copy_slot: usize,
        byte_offset: usize,
        byte_len: usize,
    ) -> Vec<u8> {
        if byte_len == 0 {
            return Vec::new();
        }
        let copy = copies[copy_slot];
        (0..byte_len)
            .map(|offset| synthetic_byte(copy.handle_id, copy.src + (byte_offset + offset) as u64))
            .collect()
    }

    fn materialize_request(request: ResidentReadbackCopy) -> Vec<u8> {
        (0..request.byte_len)
            .map(|offset| synthetic_byte(request.handle_id, request.src + offset as u64))
            .collect()
    }

    fn synthetic_byte(handle_id: u64, src: u64) -> u8 {
        handle_id
            .wrapping_mul(131)
            .wrapping_add(src.wrapping_mul(17))
            .wrapping_add(29) as u8
    }

    fn next_u64(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }
}
