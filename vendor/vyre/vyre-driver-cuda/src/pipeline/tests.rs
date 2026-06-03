use std::sync::Arc;

use smallvec::smallvec;
use vyre_driver::binding::{Binding, BindingPlan, BindingRole};
use vyre_driver::replace_output_buffers_preserving_slots;
use vyre_driver::LaunchPlan;

use crate::backend::CudaDispatchPlan;
use crate::synthetic_device_caps::blackwell_sm120_caps;

use super::{
    add_shape_bytes, cuda_graph_lane_count_for_batch, materialized_input_key,
    MaterializedPipelineOutputCache, MaterializedPipelineOutputCacheEntry,
    MAX_GRAPH_CACHE_ENTRIES_PER_PIPELINE, MAX_MATERIALIZED_OUTPUT_CACHE_BYTES_PER_PIPELINE,
};

fn single_input_output_plan(byte_len: usize) -> CudaDispatchPlan {
    CudaDispatchPlan {
        bindings: BindingPlan {
            bindings: vec![Binding {
                name: Arc::from("state"),
                binding: 0,
                buffer_index: 0,
                role: BindingRole::InputOutput,
                element_size: 1,
                preferred_alignment: 1,
                element_count: byte_len as u32,
                static_byte_len: Some(byte_len),
                input_index: Some(0),
                output_index: Some(0),
            }],
            input_indices: vec![0],
            output_indices: vec![0],
            shared_indices: vec![],
        },
        output_binding_indices: smallvec![0],
        launch: LaunchPlan {
            grid: [1, 1, 1],
            workgroup: [128, 1, 1],
            element_count: byte_len as u32,
            param_words: vec![1, 2, 3, 4],
            max_binding_alignment: 1,
        },
        cooperative: false,
        fixpoint_iterations: 1,
    }
}

#[test]
fn cuda_pipeline_dynamic_dispatch_reuses_existing_output_slots() {
    let mut outputs = vec![Vec::with_capacity(8), Vec::with_capacity(4)];
    let outputs_addr = outputs.as_ptr() as usize;
    let first_slot_addr = outputs[0].as_ptr() as usize;
    let second_slot_addr = outputs[1].as_ptr() as usize;

    replace_output_buffers_preserving_slots(vec![vec![1, 2, 3], vec![4]], &mut outputs);

    assert_eq!(outputs, vec![vec![1, 2, 3], vec![4]]);
    assert_eq!(outputs.as_ptr() as usize, outputs_addr);
    assert_eq!(outputs[0].as_ptr() as usize, first_slot_addr);
    assert_eq!(outputs[1].as_ptr() as usize, second_slot_addr);
}

#[test]
fn cuda_graph_lane_planner_scales_past_legacy_four_lane_cap() {
    let caps = blackwell_sm120_caps(32 * 1024 * 1024 * 1024);
    let plan = single_input_output_plan(1024);
    let input = vec![7_u8; 1024];
    let row = [input.as_slice()];
    let batches: Vec<&[&[u8]]> = vec![row.as_slice(); 64];

    let lanes = cuda_graph_lane_count_for_batch(&caps, &plan, &batches)
        .expect("Fix: graph replay lane planning should fit");

    assert!(lanes > 4);
    assert_eq!(lanes, 22);
}

#[test]
fn cuda_graph_lane_planner_caps_large_graphs_by_vram_budget() {
    let caps = blackwell_sm120_caps(512 * 1024 * 1024);
    let plan = single_input_output_plan(64 * 1024 * 1024);
    let input = vec![1_u8; 64 * 1024 * 1024];
    let row = [input.as_slice()];
    let batches: Vec<&[&[u8]]> = vec![row.as_slice(); 64];

    let lanes = cuda_graph_lane_count_for_batch(&caps, &plan, &batches)
        .expect("Fix: graph replay lane planning should fit");

    assert_eq!(lanes, 1);
}

#[test]
fn cuda_graph_replay_is_release_default_not_opt_in_debug_path() {
    let source = include_str!("../instrumentation.rs");
    let pipeline_source = include_str!("../pipeline.rs");

    assert!(
        source.contains("VYRE_CUDA_GRAPH_REPLAY")
            && source.contains("cached_enabled_default_true")
            && source.contains("CUDA_GRAPH_REPLAY_DISABLED"),
        "Fix: CUDA graph replay must be enabled by default with only an explicit debug disable."
    );
    assert!(
        pipeline_source.contains("crate::instrumentation::cuda_graph_replay_enabled()")
            && !pipeline_source.contains("std::env::var(\"VYRE_CUDA_GRAPH_REPLAY\")")
            && !pipeline_source.contains("var_os(\"VYRE_CUDA_GRAPH_REPLAY\")"),
        "Fix: CUDA graph replay must not be opt-in on the release path."
    );
}

#[test]
fn static_launch_param_upload_sync_is_telemetry_visible() {
    let source = include_str!("static_params.rs");
    assert!(
        source.contains("enum StaticParamUploadFailure")
            && source.contains("Completed(BackendError)")
            && source.contains("CompletionUnproven(BackendError)"),
        "Fix: CUDA static launch parameter upload must distinguish completed cleanup failures from unproven in-flight failures."
    );
    let upload = source
        .split("pub(crate) fn upload_static_launch_params")
        .nth(1)
        .expect("Fix: CUDA static launch parameter upload helper must exist.");
    assert!(
        upload.contains("backend.telemetry.record_sync_point();"),
        "Fix: CUDA compiled-pipeline static parameter upload must record its stream synchronization in telemetry."
    );
    assert!(
        upload.contains("if let Err(error) = enqueue_result")
            && upload.contains("match stream.synchronize()")
            && upload.contains("In-flight static parameter upload resources will not be recycled.")
            && upload.contains("std::mem::forget(stream);")
            && upload.contains("StaticParamUploadFailure::CompletionUnproven(error)"),
        "Fix: CUDA compiled-pipeline static parameter upload must not recycle its stream after enqueue errors unless completion is proven."
    );
    assert!(
        upload.contains("Err(StaticParamUploadFailure::Completed(err)) =>")
            && upload.contains("backend.transient_pool.release(allocation);")
            && upload.contains("Err(StaticParamUploadFailure::CompletionUnproven(err)) =>")
            && upload.contains("let _unreleased_allocation = allocation;")
            && upload.contains("std::mem::forget(host_transfers);"),
        "Fix: CUDA compiled-pipeline static parameter upload must not recycle device or host staging allocations when upload completion is unproven."
    );
    let unproven_cleanup = upload
        .split("Err(StaticParamUploadFailure::CompletionUnproven(err)) =>")
        .nth(1)
        .expect("Fix: static parameter upload must have unproven-completion cleanup.")
        .split("backend.telemetry.record_host_to_device_bytes")
        .next()
        .expect("Fix: unproven static upload cleanup must precede success telemetry.");
    assert!(
        !unproven_cleanup.contains("transient_pool.release"),
        "Fix: CUDA static parameter upload must not return unproven in-flight device memory to the transient pool."
    );
    assert!(
        upload.contains("if let Err(error) = stream.synchronize()")
            && upload.contains("backend.telemetry.record_sync_point();")
            && upload.contains("backend.launch_resources.release_stream(stream);"),
        "Fix: CUDA compiled-pipeline static parameter upload must check synchronization before telemetry or stream release."
    );
    let sync_pos = upload
        .find("if let Err(error) = stream.synchronize()")
        .expect("Fix: static parameter upload must synchronize before releasing the stream.");
    let telemetry_pos = upload
        .rfind("backend.telemetry.record_sync_point();")
        .expect("Fix: static parameter upload must record sync telemetry after success.");
    let release_pos = upload
        .rfind("backend.launch_resources.release_stream(stream);")
        .expect("Fix: static parameter upload must release the stream after successful synchronization.");
    assert!(
        sync_pos < telemetry_pos && telemetry_pos < release_pos,
        "Fix: CUDA compiled-pipeline static parameter upload must prove completion before telemetry or pooled stream release."
    );
}

#[test]
fn cuda_graph_shape_bytes_overflow_fails_loudly_without_saturating_arithmetic() {
    assert_eq!(add_shape_bytes(usize::MAX - 1, 1).unwrap(), usize::MAX);
    let overflow = add_shape_bytes(usize::MAX - 1, 2);
    assert!(
        matches!(overflow, Err(vyre_driver::BackendError::InvalidProgram { .. })),
        "Fix: CUDA graph replay shape byte overflow must return a typed error instead of capping or panicking."
    );

    let source = include_str!("../pipeline.rs");
    assert!(
        !source.contains(concat!(".saturating_add", "(CUDA_GRAPH_REPLAY_SMS_PER_LANE"))
            && !source.contains(concat!("bytes = bytes", ".saturating_add")),
        "Fix: CUDA graph lane planning must use exact arithmetic with an explicit overflow cap, not generic saturating arithmetic."
    );
    assert!(
        !source.contains("unwrap_or(usize::MAX)"),
        "Fix: CUDA graph replay shape byte overflow must not silently cap to usize::MAX."
    );
}

#[test]
fn compiled_cuda_graph_batched_replay_uses_checked_batch_lane_and_output_slots() {
    let source = include_str!("compiled_dispatch.rs");

    assert!(
        source.contains("fn compiled_graph_batch_inputs")
            && source.contains("fn compiled_graph_output_mut")
            && source.contains("fn compiled_graph_lane")
            && source.contains("fn compiled_graph_lane_mut")
            && source.contains(".get(batch_index)")
            && source.contains(".get_mut(batch_index)")
            && source.contains("miss_batches\n                .first()\n                .copied()")
            && source.contains(".get(lane)")
            && source.contains(".get_mut(lane)"),
        "Fix: compiled CUDA graph batched replay must use typed accessors for batch inputs, output slots, and lane slots."
    );
    assert!(
        !source.contains("batches[batch_index]")
            && !source.contains("outputs[batch_index]")
            && !source.contains("batches[launched_batch.batch_index]")
            && !source.contains("outputs[launched_batch.batch_index]")
            && !source.contains("miss_batches[0]")
            && !source.contains(concat!("lanes", "[lane]"))
            && !source.contains("lanes[launched_batch.lane]"),
        "Fix: compiled CUDA graph batched replay must return BackendError for stale replay indexes instead of panicking on direct indexing."
    );
    assert!(
        source.contains("fn finish_and_return_cuda_graph_lanes_after_error")
            && source.contains("fn return_cached_graph_lanes_after_error")
            && source.contains("fn finish_cuda_graph_lane_replay_discarding_outputs")
            && source.contains("return self.finish_and_return_cuda_graph_lanes_after_error(")
            && source.contains("return self.return_cached_graph_lanes_after_error(lanes, error)")
            && source.matches("std::mem::forget(lanes);").count() >= 2
            && source.matches("std::mem::forget(cached);").count() >= 2
            && !source.contains("finish_cuda_graph_indexed_lane_replays(&mut lanes, launched, outputs)?")
            && !source.contains("compiled_graph_output_mut(\n                            outputs,\n                            batch_index,\n                            \"materialized cache probe\",\n                        )?"),
        "Fix: compiled CUDA graph batched replay must finish launched lanes and either return reusable cached graph lanes or leak unproven-completion lanes instead of bypassing cleanup with direct `?` exits."
    );
    let timed_single = source
        .split("fn dispatch_borrowed_timed(")
        .nth(1)
        .expect("Fix: timed compiled-pipeline dispatch must remain present.")
        .split("fn dispatch_borrowed_into(")
        .next()
        .expect("Fix: timed compiled-pipeline dispatch must precede untimed dispatch.");
    let untimed_single = source
        .split("fn dispatch_borrowed_into(")
        .nth(1)
        .expect("Fix: untimed compiled-pipeline dispatch must remain present.")
        .split("fn dispatch_borrowed_batched(")
        .next()
        .expect("Fix: untimed compiled-pipeline dispatch must precede batched dispatch.");
    assert!(
        timed_single.contains("self.return_cached_graph(cached)?")
            && timed_single.contains("std::mem::forget(cached);")
            && untimed_single.contains("self.return_cached_graph(cached)?")
            && untimed_single.contains("std::mem::forget(cached);"),
        "Fix: single CUDA graph replay must return cached graphs only after successful replay and leak them when replay completion is unproven."
    );
    assert!(
        timed_single.contains("let input_key = materialized_input_key(inputs)?;")
            && timed_single.contains("materialized_output_cache_hit_with_key_into(inputs, &input_key")
            && timed_single.contains("take_cached_graph_with_replay_state(inputs, &input_key)")
            && timed_single.contains("Some(selection) => (selection.graph, selection.input_state)")
            && timed_single.contains("prepare_cuda_graph_replay_input_state_with_key")
            && timed_single.contains("&cached")
            && timed_single.contains("input_key")
            && timed_single.contains("dispatch_via_cuda_graph_timed_with_input_state_into")
            && timed_single.contains("remember_materialized_output_cache_with_key(inputs, input_key"),
        "Fix: timed single CUDA graph replay must reuse one exact-input key and one validated cached-graph input state across pipeline cache, graph selection, raw graph replay, and materialized-cache storage."
    );
    assert!(
        untimed_single.contains("let input_key = materialized_input_key(inputs)?;")
            && untimed_single.contains("materialized_output_cache_hit_with_key_into(inputs, &input_key")
            && untimed_single.contains("take_cached_graph_with_replay_state(inputs, &input_key)")
            && untimed_single.contains("Some(selection) => (selection.graph, selection.input_state)")
            && untimed_single.contains("prepare_cuda_graph_replay_input_state_with_key")
            && untimed_single.contains("&cached")
            && untimed_single.contains("input_key")
            && untimed_single.contains("dispatch_via_cuda_graph_with_input_state_into")
            && untimed_single.contains("remember_materialized_output_cache_with_key(inputs, input_key"),
        "Fix: untimed single CUDA graph replay must reuse one exact-input key and one validated cached-graph input state across pipeline cache, graph selection, raw graph replay, and materialized-cache storage."
    );
    assert!(
        source.contains("fn materialized_output_cache_hit_with_key_into")
            && source.contains("cache.snapshot_with_key(inputs, input_key)")
            && source.contains("fn take_cached_graph_with_key")
            && source.contains("fn take_cached_graph_with_replay_state")
            && source.contains("struct CachedGraphReplaySelection")
            && source.contains("first_shape_match = Some((index, input_state));")
            && source.contains("graph: graphs.swap_remove(index)")
            && source.contains("materialized_output_cache_matches_with_input_state(inputs, &input_state)")
            && source.contains("fn remember_materialized_output_cache_with_key")
            && !source.contains("fn take_cached_graph(")
            && !source.contains("fn remember_materialized_output_cache("),
        "Fix: compiled CUDA graph single replay helpers must consume precomputed input keys and carry validated replay input state out of graph-cache selection instead of recomputing it."
    );
    let batched_replay = source
        .split("fn dispatch_borrowed_batched_via_cuda_graph_lanes")
        .nth(1)
        .expect("Fix: batched compiled-pipeline graph replay must remain present.")
        .split("fn materialized_output_batch_cache_partition_into")
        .next()
        .expect("Fix: batched compiled-pipeline graph replay must precede materialized cache partition.");
    assert!(
        batched_replay.contains("let first_miss")
            && batched_replay.contains("miss_entries")
            && batched_replay.contains("take_cached_graph_with_key(")
            && batched_replay.contains("first_miss_batch")
            && batched_replay.contains("&first_miss.input_key")
            && !batched_replay.contains("take_cached_graph(first_miss_batch)"),
        "Fix: batched CUDA graph lane seeding must reuse the partitioned miss input key for graph-cache selection instead of hashing the first miss again."
    );
    let finish_helper = source
        .split("fn finish_cuda_graph_indexed_lane_replays")
        .nth(1)
        .expect("Fix: compiled CUDA graph replay must expose indexed lane finishing.")
        .split("fn finish_and_return_cuda_graph_lanes_after_error")
        .next()
        .expect("Fix: compiled CUDA graph lane finishing must precede error-return helper.");
    assert!(
        finish_helper.contains("finish_cuda_graph_lane_replay_discarding_outputs")
            && finish_helper.contains("lane.output_host_bufs.len()")
            && finish_helper.contains("\"discarded cuda graph lane output\"")
            && finish_helper.contains("finish_cuda_graph_replay_into(lane, replay_stats, &mut discard_outputs)"),
        "Fix: launched CUDA graph lanes must be fenced through finish_cuda_graph_replay_into even when caller output-slot lookup fails."
    );
}

#[test]
fn materialized_input_key_separates_tuple_boundaries_for_4096_generated_cases() {
    for seed in 0_u32..4096 {
        let left_len = ((seed.wrapping_mul(17) ^ seed.rotate_left(5)) % 31 + 1) as usize;
        let right_len = ((seed.wrapping_mul(29) ^ seed.rotate_left(9)) % 31 + 1) as usize;
        let mut state = seed ^ 0xC0DA_CAFE;
        let mut left = Vec::with_capacity(left_len);
        let mut right = Vec::with_capacity(right_len);
        for index in 0..left_len {
            state = state
                .wrapping_mul(1_664_525)
                .wrapping_add(1_013_904_223)
                .rotate_left((index as u32) & 15);
            left.push((state ^ seed.rotate_left(index as u32 & 31)) as u8);
        }
        for index in 0..right_len {
            state = state
                .wrapping_mul(22_695_477)
                .wrapping_add(1)
                .rotate_left((index as u32) & 7);
            right.push((state ^ seed.rotate_right(index as u32 & 31)) as u8);
        }
        let mut concatenated = Vec::with_capacity(left_len + right_len);
        concatenated.extend_from_slice(&left);
        concatenated.extend_from_slice(&right);

        let tuple_key = materialized_input_key(&[left.as_slice(), right.as_slice()])
            .expect("Fix: generated tuple materialized-input key must fit");
        let concatenated_key = materialized_input_key(&[concatenated.as_slice()])
            .expect("Fix: generated concatenated materialized-input key must fit");
        let empty_separated_key = materialized_input_key(&[left.as_slice(), &[], right.as_slice()])
            .expect("Fix: generated empty-separated materialized-input key must fit");

        assert_ne!(
            tuple_key, concatenated_key,
            "Fix: materialized CUDA output cache key must length-prefix inputs so tuple boundaries cannot alias for generated case {seed}."
        );
        assert_ne!(
            tuple_key, empty_separated_key,
            "Fix: materialized CUDA output cache key must include empty input slots instead of collapsing them for generated case {seed}."
        );
    }
}

#[test]
fn materialized_input_key_changes_on_4096_single_byte_mutations() {
    for seed in 0_u32..4096 {
        let len = ((seed.wrapping_mul(37) ^ seed.rotate_left(11)) % 96 + 1) as usize;
        let mut bytes = Vec::with_capacity(len);
        let mut state = seed ^ 0xA5A5_5A5A;
        for index in 0..len {
            state = state
                .wrapping_mul(1_103_515_245)
                .wrapping_add(12_345)
                .rotate_left((index as u32) & 15);
            bytes.push((state >> ((index & 3) * 8)) as u8);
        }
        let mut mutated = bytes.clone();
        let mutation_index = (seed as usize) % len;
        mutated[mutation_index] ^= 0x80 | ((seed as u8) & 0x7f);

        let base_key = materialized_input_key(&[bytes.as_slice()])
            .expect("Fix: base generated materialized-input key must fit");
        let mutated_key = materialized_input_key(&[mutated.as_slice()])
            .expect("Fix: mutated generated materialized-input key must fit");

        assert_ne!(
            base_key, mutated_key,
            "Fix: materialized CUDA output cache key must change when one byte changes for generated case {seed}."
        );
    }
}

#[test]
fn materialized_output_cache_hits_4096_generated_exact_inputs() {
    let mut cache = MaterializedPipelineOutputCache::default();
    for seed in 0_u32..4096 {
        let input_len = ((seed.wrapping_mul(19) ^ seed.rotate_left(3)) % 128 + 1) as usize;
        let output_len = ((seed.wrapping_mul(23) ^ seed.rotate_left(7)) % 128 + 1) as usize;
        let mut state = seed ^ 0xD15C_A11E;
        let mut input = Vec::with_capacity(input_len);
        for index in 0..input_len {
            state = state
                .wrapping_mul(1_664_525)
                .wrapping_add(1_013_904_223)
                .rotate_left((index as u32) & 15);
            input.push((state >> ((index & 3) * 8)) as u8);
        }
        let mut output = Vec::with_capacity(output_len);
        for index in 0..output_len {
            state = state
                .wrapping_mul(22_695_477)
                .wrapping_add(1)
                .rotate_left((index as u32) & 7);
            output.push((state ^ seed.rotate_left(index as u32 & 31)) as u8);
        }
        let outputs = vec![output];
        cache
            .remember(&[input.as_slice()], &outputs)
            .expect("Fix: generated materialized CUDA output cache insert must fit");

        let mut replayed = vec![Vec::with_capacity(output_len + 31)];
        assert!(
            cache
                .hit_into(&[input.as_slice()], &mut replayed)
                .expect("Fix: generated materialized CUDA output cache hit must fit"),
            "Fix: materialized CUDA output cache must hit immediately for generated exact input case {seed}."
        );
        assert_eq!(
            replayed, outputs,
            "Fix: materialized CUDA output cache must replay exact output bytes for generated case {seed}."
        );
        assert!(
            cache.len() <= MAX_GRAPH_CACHE_ENTRIES_PER_PIPELINE,
            "Fix: materialized CUDA output cache must enforce the bounded entry count."
        );
        assert!(
            cache.byte_len() <= MAX_MATERIALIZED_OUTPUT_CACHE_BYTES_PER_PIPELINE,
            "Fix: materialized CUDA output cache must enforce the bounded byte budget."
        );
    }
}

#[test]
fn materialized_output_cache_replaces_same_key_without_double_counting_bytes() {
    let mut cache = MaterializedPipelineOutputCache::default();
    let input = b"same compiled CUDA graph replay input";
    let outputs_a = vec![b"old output".to_vec()];
    let outputs_b = vec![b"new output with a different byte length".to_vec()];

    cache
        .remember(&[input.as_slice()], &outputs_a)
        .expect("Fix: first materialized output cache insert must fit");
    assert_eq!(cache.len(), 1);
    let first_bytes = cache.byte_len();
    assert_eq!(first_bytes, input.len() + outputs_a[0].len());

    cache
        .remember(&[input.as_slice()], &outputs_b)
        .expect("Fix: same-key materialized output cache replacement must fit");
    assert_eq!(
        cache.len(),
        1,
        "Fix: same-key materialized output cache replacement must not create duplicate entries."
    );
    assert_eq!(
        cache.byte_len(),
        input.len() + outputs_b[0].len(),
        "Fix: same-key materialized output cache replacement must subtract the old entry before adding the new one."
    );

    let mut replayed = Vec::new();
    assert!(cache
        .hit_into(&[input.as_slice()], &mut replayed)
        .expect("Fix: same-key materialized output cache hit must fit"));
    assert_eq!(
        replayed, outputs_b,
        "Fix: same-key materialized output cache hit must return the newest output bytes."
    );
}

#[test]
fn materialized_output_snapshot_survives_same_key_replacement() {
    let mut cache = MaterializedPipelineOutputCache::default();
    let input = b"snapshot input retained outside the CUDA graph cache lock";
    let outputs_a = vec![b"snapshot bytes copied after lock release".to_vec()];
    let outputs_b = vec![b"replacement bytes stored by another replay".to_vec()];

    cache
        .remember(&[input.as_slice()], &outputs_a)
        .expect("Fix: initial materialized output snapshot fixture insert must fit");
    let snapshot = cache
        .snapshot(&[input.as_slice()])
        .expect("Fix: materialized output snapshot lookup must fit")
        .expect("Fix: materialized output snapshot must exist for exact input");

    cache
        .remember(&[input.as_slice()], &outputs_b)
        .expect("Fix: same-key materialized output replacement must fit after snapshot");

    let mut replayed_from_snapshot = Vec::new();
    snapshot
        .copy_into(&mut replayed_from_snapshot)
        .expect("Fix: materialized output snapshot copy after replacement must fit");
    assert_eq!(
        replayed_from_snapshot, outputs_a,
        "Fix: CUDA materialized cache hit snapshots must keep immutable output ownership so dispatch can copy after releasing the cache lock."
    );

    let mut replayed_from_cache = Vec::new();
    assert!(cache
        .hit_into(&[input.as_slice()], &mut replayed_from_cache)
        .expect("Fix: post-replacement materialized cache hit must fit"));
    assert_eq!(
        replayed_from_cache, outputs_b,
        "Fix: same-key replacement must still expose the newest cached output after an older snapshot escapes the cache lock."
    );
}

#[test]
fn materialized_output_cache_hit_preserves_existing_output_slots_until_reservation_succeeds() {
    let source = include_str!("materialized_cache.rs");
    let copier = source
        .split("fn copy_materialized_outputs_into(")
        .nth(1)
        .expect("Fix: materialized cache must expose output copy helper.")
        .split("fn clone_materialized_cache_bytes(")
        .next()
        .expect("Fix: materialized output copy helper must precede byte clone helper.");
    let reserve_pos = copier
        .find("try_reserve_exact(source.len() - target.capacity())")
        .expect("Fix: materialized cache hit must reserve existing output bytes before mutation.");
    let append_clone_pos = copier
        .find("clone_materialized_cache_bytes(\n                source,\n                \"new output destination bytes\"")
        .expect("Fix: materialized cache hit must build new output slots before mutating the caller output vector.");
    let truncate_pos = copier
        .find("dst.truncate(outputs.len());")
        .expect("Fix: materialized cache hit must trim stale caller slots only after reservation.");
    let clear_pos = copier
        .find("target.clear();\n        target.extend_from_slice(source);")
        .expect("Fix: materialized cache hit must rewrite existing output slots after reservation.");

    assert!(
        reserve_pos < truncate_pos
            && append_clone_pos < truncate_pos
            && truncate_pos < clear_pos
            && copier.contains("dst.extend(appended_outputs);")
            && !copier.contains("target.clear();\n        target.try_reserve"),
        "Fix: CUDA materialized output cache hits must reserve/build output storage before truncating or clearing caller-owned outputs."
    );

    let mut cache = MaterializedPipelineOutputCache::default();
    let input = b"capacity-preserving materialized cache input";
    let outputs = vec![b"cached output a".to_vec(), b"cached output b".to_vec()];
    cache
        .remember(&[input.as_slice()], &outputs)
        .expect("Fix: materialized cache insert must fit capacity-preservation fixture.");

    let mut replayed = vec![
        Vec::with_capacity(64),
        Vec::with_capacity(32),
        b"stale extra output".to_vec(),
    ];
    replayed[0].extend_from_slice(b"old-a");
    replayed[1].extend_from_slice(b"old-b");
    let first_capacity = replayed[0].capacity();
    let second_capacity = replayed[1].capacity();

    assert!(
        cache
            .hit_into(&[input.as_slice()], &mut replayed)
            .expect("Fix: materialized cache hit must fit capacity-preservation fixture."),
        "Fix: materialized cache must hit exact capacity-preservation fixture input."
    );
    assert_eq!(replayed, outputs);
    assert_eq!(replayed[0].capacity(), first_capacity);
    assert_eq!(replayed[1].capacity(), second_capacity);
}

#[test]
fn materialized_output_cache_prebuilt_entries_match_direct_remember_for_1024_cases() {
    for seed in 0_u32..1024 {
        let input_len = ((seed.wrapping_mul(11) ^ seed.rotate_left(13)) % 96 + 1) as usize;
        let output_len = ((seed.wrapping_mul(31) ^ seed.rotate_left(5)) % 96 + 1) as usize;
        let mut state = seed ^ 0xCACA_5000;
        let mut input = Vec::with_capacity(input_len);
        for index in 0..input_len {
            state = state
                .wrapping_mul(1_664_525)
                .wrapping_add(1_013_904_223)
                .rotate_left((index as u32) & 15);
            input.push((state >> ((index & 3) * 8)) as u8);
        }
        let mut output = Vec::with_capacity(output_len);
        for index in 0..output_len {
            state = state
                .wrapping_mul(22_695_477)
                .wrapping_add(1)
                .rotate_left((index as u32) & 7);
            output.push((state ^ seed.rotate_right(index as u32 & 31)) as u8);
        }
        let outputs = vec![output];
        let mut direct = MaterializedPipelineOutputCache::default();
        direct
            .remember(&[input.as_slice()], &outputs)
            .expect("Fix: direct materialized cache remember must fit");
        let mut prebuilt = MaterializedPipelineOutputCache::default();
        let entry = MaterializedPipelineOutputCacheEntry::new(&[input.as_slice()], &outputs)
            .expect("Fix: prebuilt materialized cache entry construction must fit");
        prebuilt
            .remember_entry(entry)
            .expect("Fix: prebuilt materialized cache entry insertion must fit");
        let input_key = materialized_input_key(&[input.as_slice()])
            .expect("Fix: generated materialized input key must fit");
        let mut keyed = MaterializedPipelineOutputCache::default();
        let keyed_entry = MaterializedPipelineOutputCacheEntry::new_with_key(
            &[input.as_slice()],
            &input_key,
            &outputs,
        )
        .expect("Fix: keyed materialized cache entry construction must fit");
        keyed
            .remember_entry(keyed_entry)
            .expect("Fix: keyed materialized cache entry insertion must fit");

        let mut direct_replay = Vec::new();
        let mut prebuilt_replay = Vec::new();
        let mut keyed_replay = Vec::new();
        assert!(
            direct
                .hit_into(&[input.as_slice()], &mut direct_replay)
                .expect("Fix: direct materialized cache hit must fit"),
            "Fix: direct materialized cache must hit for generated case {seed}."
        );
        assert!(
            prebuilt
                .hit_into(&[input.as_slice()], &mut prebuilt_replay)
                .expect("Fix: prebuilt materialized cache hit must fit"),
            "Fix: prebuilt materialized cache must hit for generated case {seed}."
        );
        assert!(
            keyed
                .hit_into(&[input.as_slice()], &mut keyed_replay)
                .expect("Fix: keyed materialized cache hit must fit"),
            "Fix: keyed materialized cache must hit for generated case {seed}."
        );
        assert_eq!(
            prebuilt_replay, direct_replay,
            "Fix: prebuilt materialized cache insertion must preserve exact outputs for generated case {seed}."
        );
        assert_eq!(
            keyed_replay, direct_replay,
            "Fix: keyed materialized cache insertion must preserve exact outputs for generated case {seed}."
        );
        assert_eq!(
            prebuilt.byte_len(),
            direct.byte_len(),
            "Fix: prebuilt materialized cache insertion must preserve byte accounting for generated case {seed}."
        );
        assert_eq!(
            keyed.byte_len(),
            direct.byte_len(),
            "Fix: keyed materialized cache insertion must preserve byte accounting for generated case {seed}."
        );
    }
}

#[test]
fn materialized_output_cache_evicts_oldest_entries_under_generated_pressure() {
    let mut cache = MaterializedPipelineOutputCache::default();
    let total_entries = MAX_GRAPH_CACHE_ENTRIES_PER_PIPELINE + 17;
    for seed in 0..total_entries {
        let input = (seed as u32).to_le_bytes().to_vec();
        let outputs = vec![vec![seed as u8; 8]];
        cache
            .remember(&[input.as_slice()], &outputs)
            .expect("Fix: generated materialized output cache pressure insert must fit");
    }

    assert_eq!(
        cache.len(),
        MAX_GRAPH_CACHE_ENTRIES_PER_PIPELINE,
        "Fix: materialized output cache must evict oldest entries instead of growing past its bounded lane-cache size."
    );
    assert_eq!(
        cache.byte_len(),
        MAX_GRAPH_CACHE_ENTRIES_PER_PIPELINE * (std::mem::size_of::<u32>() + 8),
        "Fix: materialized output cache byte accounting must track evicted entries exactly under generated pressure."
    );

    let evicted_input = 0_u32.to_le_bytes().to_vec();
    let mut evicted_replay = vec![b"sentinel".to_vec()];
    assert!(
        !cache
            .hit_into(&[evicted_input.as_slice()], &mut evicted_replay)
            .expect("Fix: evicted materialized output lookup must stay fallible"),
        "Fix: oldest generated materialized output entry must be evicted when capacity is exceeded."
    );
    assert_eq!(
        evicted_replay,
        vec![b"sentinel".to_vec()],
        "Fix: materialized output cache miss must not mutate caller-owned output buffers."
    );

    let retained_seed = (total_entries - 1) as u32;
    let retained_input = retained_seed.to_le_bytes().to_vec();
    let mut retained_replay = Vec::new();
    assert!(
        cache
            .hit_into(&[retained_input.as_slice()], &mut retained_replay)
            .expect("Fix: retained materialized output lookup must fit"),
        "Fix: newest generated materialized output entry must remain cached after pressure eviction."
    );
    assert_eq!(
        retained_replay,
        vec![vec![retained_seed as u8; 8]],
        "Fix: retained generated materialized output entry must replay exact bytes after evictions."
    );
}

#[test]

fn materialized_output_cache_rejects_oversized_entries_without_polluting_cache() {
    let mut cache = MaterializedPipelineOutputCache::default();
    let input = b"oversized compiled CUDA graph replay input";
    let outputs = vec![vec![
        0xA5;
        MAX_MATERIALIZED_OUTPUT_CACHE_BYTES_PER_PIPELINE + 1
    ]];

    cache
        .remember(&[input.as_slice()], &outputs)
        .expect("Fix: oversized materialized output cache entry should be a typed no-admission path, not an allocation or dispatch failure.");

    assert_eq!(
        cache.len(),
        0,
        "Fix: oversized materialized output cache entries must not evict useful entries or consume cache slots."
    );
    assert_eq!(
        cache.byte_len(),
        0,
        "Fix: oversized materialized output cache entries must not perturb byte accounting."
    );
    let mut replay = Vec::new();
    assert!(
        !cache
            .hit_into(&[input.as_slice()], &mut replay)
            .expect("Fix: oversized no-admission lookup must remain fallible"),
        "Fix: oversized materialized output cache entries must not be observable as hits."
    );
}

#[test]
fn materialized_output_cache_preflights_oversized_entries_before_owning_bytes() {
    let input = b"oversized compiled CUDA graph replay input";
    let outputs = vec![vec![
        0xCC;
        MAX_MATERIALIZED_OUTPUT_CACHE_BYTES_PER_PIPELINE + 1
    ]];

    assert!(
        MaterializedPipelineOutputCacheEntry::new_if_cacheable(&[input.as_slice()], &outputs)
            .expect("Fix: oversized materialized cache preflight must be a typed no-admission path.")
            .is_none(),
        "Fix: oversized materialized cache entries must be rejected before constructing owned cache entries."
    );

    let source = include_str!("materialized_cache.rs");
    let preflight_constructor = source
        .split("pub(crate) fn new_if_cacheable")
        .nth(1)
        .expect("Fix: materialized cache must expose a preflight constructor.")
        .split("pub(crate) fn new(")
        .next()
        .expect("Fix: preflight constructor must precede the fallible owning constructor.");
    assert!(
        preflight_constructor.contains("materialized_cache_entry_byte_len_if_admissible")
            && !preflight_constructor.contains("clone_materialized_cache_bytes"),
        "Fix: materialized CUDA replay cache must compute admissibility before cloning input/output bytes."
    );
}
