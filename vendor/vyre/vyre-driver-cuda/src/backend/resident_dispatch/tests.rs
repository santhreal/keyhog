use super::helpers::{
    borrow_resident_sequence_output_slots, prepare_resident_sequence_fills,
    stage_resident_fill_payload,
};

fn resident_dispatch_production_source() -> String {
    [
        include_str!("helpers.rs"),
        include_str!("borrowed.rs"),
        include_str!("async_dispatch.rs"),
        include_str!("batch.rs"),
        include_str!("sync.rs"),
        include_str!("sequence_api.rs"),
        include_str!("sequence_fused.rs"),
        include_str!("timed.rs"),
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::{
        borrow_resident_sequence_output_slots, prepare_resident_sequence_fills,
        resident_dispatch_production_source, stage_resident_fill_payload,
    };
    use crate::backend::resident::CudaResidentBuffer;

    #[test]
    fn resident_fallback_fill_payload_preserves_last_good_bytes_when_reservation_fails() {
        let mut payload = vec![0xC3, 0xC3, 0x7E, 0x11];

        let result = stage_resident_fill_payload(&mut payload, 0x5A, usize::MAX);

        assert!(
            result.is_err(),
            "oversized CUDA resident fill payload must fail preflight instead of mutating staging"
        );
        assert_eq!(
            payload,
            vec![0xC3, 0xC3, 0x7E, 0x11],
            "failed CUDA resident fill staging must preserve the last diagnostic payload"
        );
    }
    #[test]
    fn resident_fallback_fill_payload_reuses_capacity_and_overwrites_values() {
        let mut payload = Vec::new();
        {
            let bytes = stage_resident_fill_payload(&mut payload, 0xA5, 16)
                .expect("Fix: reusable resident fallback fill staging should reserve bytes");
            assert_eq!(bytes, &[0xA5; 16]);
        }
        let initial_capacity = payload.capacity();

        {
            let bytes = stage_resident_fill_payload(&mut payload, 0x5A, 8)
                .expect("Fix: smaller resident fallback fill staging should reuse capacity");
            assert_eq!(bytes, &[0x5A; 8]);
        }
        assert_eq!(
            payload.capacity(),
            initial_capacity,
            "CUDA resident fallback fill staging must reuse capacity across fills instead of allocating one Vec per fill"
        );

        {
            let bytes = stage_resident_fill_payload(&mut payload, 0x11, 0)
                .expect("Fix: zero-byte resident fallback fill staging should be valid");
            assert!(bytes.is_empty());
        }
        assert_eq!(
            payload.capacity(),
            initial_capacity,
            "zero-byte fallback fills must not release reusable staging capacity"
        );
    }

    #[test]
    fn resident_borrowed_fallback_does_not_allocate_vec_per_fill() {
        let source = super::resident_dispatch_production_source();
        assert!(
            source.contains("stage_resident_fill_payload(&mut fill_payload")
                && source.contains("let mut fill_payload = Vec::new();")
                && !source.contains(concat!("vec![value; ", "handle.byte_len]")),
            "Fix: CUDA resident borrowed fallback must stage fills through one reusable Vec, not allocate a fresh Vec per resident clear/fill."
        );
    }

    #[test]
    fn resident_h2d_enqueues_are_single_sourced_without_stealing_stream_order() {
        let source = super::resident_dispatch_production_source();
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("Fix: resident_dispatch production source must precede tests.");
        assert!(
            production.contains("fn enqueue_resident_h2d_copy")
                && production.contains("fn enqueue_optional_resident_h2d_copy")
                && production.contains("fn enqueue_resident_upload_copies_on_stream")
                && production
                    .matches(concat!("super::copy::", "h2d_async_checked"))
                    .count()
                    == 1,
            "Fix: resident dispatch parameter uploads, sequence uploads, and per-step parameter uploads must share one local H2D enqueue helper while preserving the caller-owned CUDA stream."
        );
        assert!(
            production.contains("enqueue_resident_upload_copies_on_stream(\n                &upload_copies")
                && production.contains("enqueue_resident_h2d_copy(\n                        params_ptr")
                && production.contains("param_host_ptr,\n                        param_bytes")
                && production.contains("stream.raw(),"),
            "Fix: resident sequence uploads and per-step parameter uploads must use the shared stream-preserving enqueue helpers."
        );
    }

    #[test]
    fn resident_sequence_fills_coalesce_duplicates_and_skip_full_upload_overwrites() {
        let first = CudaResidentBuffer {
            id: 1,
            byte_len: 16,
        };
        let second = CudaResidentBuffer {
            id: 2,
            byte_len: 16,
        };
        let upload = [0xFE_u8; 16];

        let effective = prepare_resident_sequence_fills(
            &[(first, 0x11), (second, 0x22), (first, 0x33)],
            &[(second, upload.as_slice())],
        )
        .expect("Fix: generated resident sequence fill coalescing must succeed.");

        assert_eq!(
            effective.as_slice(),
            &[(first, 0x33)],
            "Fix: resident sequence fills must keep the last duplicate fill and drop fills fully overwritten by same-sequence uploads."
        );
    }

    #[test]
    fn resident_sequence_fills_handle_dense_duplicate_streams_without_changing_order() {
        let handles: Vec<_> = (0..256)
            .map(|id| CudaResidentBuffer { id, byte_len: 1 })
            .collect();
        let mut fills = Vec::new();
        for round in 0..8_u8 {
            fills.extend(handles.iter().copied().map(|handle| (handle, round)));
        }

        let upload = [0xAA_u8];
        let uploads: Vec<_> = handles
            .iter()
            .copied()
            .filter(|handle| handle.id % 2 == 0)
            .map(|handle| (handle, upload.as_slice()))
            .collect();

        let effective = prepare_resident_sequence_fills(&fills, &uploads)
            .expect("Fix: dense CUDA resident fill coalescing must reserve bounded indices.");

        assert_eq!(
            effective.len(),
            128,
            "Fix: uploaded handles must suppress same-sequence fills even under dense duplicate traffic."
        );
        for (position, (handle, value)) in effective.iter().copied().enumerate() {
            assert_eq!(
                handle.id % 2,
                1,
                "Fix: uploaded resident handle {} must not retain a redundant fill.",
                handle.id
            );
            assert_eq!(
                handle.id as usize,
                position * 2 + 1,
                "Fix: first-seen fill order must be stable after duplicate coalescing."
            );
            assert_eq!(
                value, 7,
                "Fix: duplicate resident fills must keep the final value for each handle."
            );
        }
    }

    #[test]
    fn resident_full_readback_preparation_is_single_sourced() {
        let source = super::resident_dispatch_production_source();
        assert!(
            source.contains("fn prepare_full_resident_readbacks")
                && source
                    .matches(concat!("self.", "prepare_full_resident_readbacks(read_handles"))
                    .count()
                    == 2,
            "Fix: CUDA resident full-handle readback preparation must be shared by read_many and fill_read_many paths."
        );
    }

    #[test]
    fn resident_sequence_output_slot_borrowing_is_single_sourced_and_reuses_slots() {
        let source = super::resident_dispatch_production_source();
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("Fix: resident_dispatch production source must precede tests.");
        assert!(
            production.contains("fn borrow_resident_sequence_output_slots")
                && production
                    .matches("borrow_resident_sequence_output_slots(outputs,")
                    .count()
                    == 2,
            "Fix: CUDA resident sequence read_many and fill_read_many must share output-slot borrowing."
        );

        let mut outputs = vec![vec![1, 2, 3], Vec::new(), vec![4]];
        let initial_first_capacity = outputs[0].capacity();
        {
            let borrowed = borrow_resident_sequence_output_slots(&mut outputs, 2)
                .expect("Fix: output-slot borrowing should resize existing slots.");
            assert_eq!(borrowed.len(), 2);
        }
        assert_eq!(outputs.len(), 2);
        assert!(
            outputs[0].capacity() >= initial_first_capacity,
            "Fix: resizing borrowed resident output slots must preserve existing slot allocation."
        );
    }

    #[test]
    fn resident_sequence_resolves_views_once_per_sequence() {
        let source = super::resident_dispatch_production_source();
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("Fix: resident_dispatch production source must precede tests.");

        assert!(
            production.contains("fn resolve_resident_sequence_launch_ptrs")
                && production
                    .matches("resolve_resident_sequence_launch_ptrs(step,")
                    .count()
                    == 1,
            "Fix: CUDA resident sequence launch-pointer validation must be single-sourced."
        );
        assert!(
            production.contains("let mut sequence_view_cache = ResidentViewCache::new();")
                && production.contains("resident sequence view cache")
                && !production.contains("resident sequence fill view cache")
                && !production.contains("resident sequence step view cache")
                && !production.contains("resident sequence readback view cache")
                && !production.contains("struct ClearCopy"),
            "Fix: CUDA resident sequence dispatch must use one sequence-wide resident view cache instead of rebuilding fill, step, and readback caches."
        );
    }
}
