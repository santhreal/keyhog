#[test]
fn hyperscan_compile_with_opts_delegates_compile_stages() {
    let source =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/simd/backend.rs"))
            .expect("simd backend source readable");

    assert!(
        !source.contains("~1.7 s Hyperscan compile"),
        "Hyperscan cache comments must not carry stale fixed compile-time claims; cold compile cost is host/profile dependent and warm-cache behavior is the contract"
    );

    for required in [
        "const MAX_HS_PATTERN_LEN: usize = 500;",
        "const BASE_PATTERN_COST: u64 = 16;",
        "const RETRY_THRESHOLD: usize = 100;",
        "const RETRY_DROP_DIVISOR: usize = 10;",
        "fn hs_partition_cost(",
        "fn counted_repeat_upper_bound(",
        "fn prepare_patterns(",
        "fn compile_cache_key(",
        "fn compile_shard_count(",
        "fn partition_patterns_lpt(",
        "fn compile_cached_shards(",
        "fn assemble_scanner_shards(",
        "fn scratch_pool_size()",
        "fn build_scratch_pool(",
        "fn write_cached_dropped_ids(",
        "fn read_cached_dropped_ids(",
    ] {
        assert!(
            source.contains(required),
            "simd backend must keep named compile-stage owner: {required}"
        );
    }

    let compile_body = source
        .split("pub(crate) fn compile_with_opts(")
        .nth(1)
        .expect("compile_with_opts present")
        .split("/// Build one shard")
        .next()
        .expect("compile_with_opts boundary present");

    for required_call in [
        "Self::prepare_patterns(",
        "Self::compile_cache_key(",
        "Self::compile_shard_count(",
        "Self::partition_patterns_lpt(",
        "Self::compile_cached_shards(",
        "Self::assemble_scanner_shards(",
    ] {
        assert!(
            compile_body.contains(required_call),
            "compile_with_opts must delegate stage via {required_call}"
        );
    }

    assert!(
        !compile_body.contains(".into_par_iter()")
            && !compile_body.contains("read_hs_cache_file(")
            && !compile_body.contains("Pattern::with_flags("),
        "compile_with_opts must not own pattern prep, cache I/O, or parallel shard build loops"
    );

    let assemble_body = source
        .split("fn assemble_scanner_shards(")
        .nth(1)
        .expect("assemble_scanner_shards present")
        .split("/// Compile patterns with explicit per-pattern flags.")
        .next()
        .expect("assemble_scanner_shards boundary present");
    assert!(
        assemble_body.contains("let scratch_count = Self::scratch_pool_size();")
            && assemble_body.contains("Self::build_scratch_pool(&db, shard_idx, scratch_count)?")
            && assemble_body.contains("Self::caller_pattern_indices_for_dropped(")
            && assemble_body.contains("scratch_pool: parking_lot::Mutex::new(scratch_pool)")
            && source.contains("Vec::with_capacity(scratch_count)")
            && source.contains("scratch_pool.push("),
        "Hyperscan compile must preallocate shard scratch pools so scan coverage cannot allocate opportunistically or return partial results"
    );

    let cache_key_body = source
        .split("fn compile_cache_key(")
        .nth(1)
        .expect("compile_cache_key present")
        .split("fn compile_shard_count(")
        .next()
        .expect("compile_cache_key boundary present");
    for required in [
        "let HsCompileOpts {\n            singlematch,\n            caseless,\n            shard_target: _,\n            utf8,\n        } = opts;",
        "h.update(if singlematch { b\"SM1\" } else { b\"SM0\" });",
        "h.update(if utf8 { b\"U81\" } else { b\"U80\" });",
        "None => h.update(b\"CLall\")",
        "Some(cl) =>",
        "h.update(b\"CLper\")",
        "h.update([b as u8]);",
    ] {
        assert!(
            cache_key_body.contains(required),
            "Hyperscan cache keys must encode compile profile semantics: {required}"
        );
    }

    let shard_key_body = source
        .split("fn shard_cache_key(")
        .nth(1)
        .expect("shard_cache_key present")
        .split("fn load_cached_shard(")
        .next()
        .expect("shard_cache_key boundary present");
    assert!(
        shard_key_body.contains("h.update(cache_key.as_bytes())")
            && shard_key_body.contains("h.update((shard_count as u64).to_le_bytes())")
            && shard_key_body.contains("h.update((shard_idx as u64).to_le_bytes())"),
        "Hyperscan shard cache keys must include profile key, shard count, and shard index"
    );

    let cached_body = source
        .split("fn compile_cached_shards(")
        .nth(1)
        .expect("compile_cached_shards present")
        .split("fn shard_cache_key(")
        .next()
        .expect("compile_cached_shards boundary present");
    assert!(
        cached_body.contains("if let Some((db, dropped))")
            && cached_body.contains("return Ok((db, dropped));")
            && cached_body.contains("Self::persist_cached_shard(&db, &dropped")
            && !cached_body.contains("return Ok((db, Vec::new()));"),
        "Hyperscan shard cache hits must preserve compile-time dropped ids so warm-cache scans reroute unsupported patterns exactly like cold compiles"
    );
    assert!(
        source.contains("fn caller_pattern_indices_for_dropped(")
            && source.contains("pattern_map: &[(usize, usize, usize, bool)]")
            && source.contains("pattern_map.get(hs_id)")
            && source.contains("map(|(input_idx, _, _, _)| *input_idx)")
            && source.contains("returned dropped pattern id")
            && source.contains("outside pattern map len"),
        "Hyperscan compile retry/cache dropped ids must be translated from compact HS ids back to caller input pattern indices before rerouting"
    );

    let partition_body = source
        .split("fn partition_patterns_lpt(")
        .nth(1)
        .expect("partition_patterns_lpt present")
        .split("fn compile_cached_shards(")
        .next()
        .expect("partition_patterns_lpt boundary present");
    assert!(
        partition_body.contains("order.sort_unstable_by(")
            && partition_body.contains(".expression")
            && partition_body.contains("let costs: Vec<u64>")
            && partition_body.contains("hs_partition_cost(&pattern.expression)")
            && partition_body.contains("shard_cost[lightest].saturating_add(costs[i])")
            && partition_body.contains(".then_with(|| hs_pats[a].id.cmp(&hs_pats[b].id))")
            && partition_body.contains(".then_with(|| a.cmp(&b))")
            && !partition_body.contains("sort_unstable_by_key"),
        "Hyperscan LPT partitioning must balance estimated compile cost with deterministic tie-breakers so heavy patterns do not churn shard cache keys or serialize one shard"
    );

    let prepare_body = source
        .split("fn prepare_patterns(")
        .nth(1)
        .expect("prepare_patterns present")
        .split("fn pattern_flags(")
        .next()
        .expect("prepare_patterns boundary present");
    assert!(
        !prepare_body.contains("hs_partition_cost(")
            && !prepare_body.contains("MAX_HS_COMPILE_COST")
            && prepare_body.contains(".par_iter()")
            && prepare_body.contains("pattern.id = Some(pattern_map.len())")
            && prepare_body.contains("input_index: i")
            && prepare_body.contains("pattern_map.push((input_index, det_idx, pat_idx, has_group))"),
        "Hyperscan prepare must parallelize pattern validation, preserve caller input indices, and assign compact stable HS ids serially"
    );

    let validate_opts_body = source
        .split("fn validate_compile_opts(")
        .nth(1)
        .expect("validate_compile_opts present")
        .split("fn compile_cache_key(")
        .next()
        .expect("validate_compile_opts boundary present");
    assert!(
        validate_opts_body.contains("caseless.len() != pattern_count")
            && validate_opts_body.contains("refusing silent CASELESS default"),
        "per-pattern Hyperscan flags must fail closed when their length drifts from the input pattern set"
    );
    assert!(
        source.contains("Self::validate_compile_opts(patterns.len(), opts)?;")
            && source.contains("Some(flags) => flags[index]")
            && !source.contains("flags.get(index).copied().unwrap_or(true)"),
        "compile_with_opts must validate per-pattern flags before indexing; missing entries must not default to CASELESS"
    );
}

#[test]
fn hyperscan_call_sites_use_distinct_cache_profiles() {
    let backend_prepared = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/backend_prepared.rs"
    ))
    .expect("backend_prepared source readable");
    let phase2_hs = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/phase2_hs.rs"
    ))
    .expect("phase2_hs source readable");

    assert!(
        backend_prepared.contains("HsCompileOpts {")
            && backend_prepared.contains("shard_target: tuning.hs_shard_target")
            && backend_prepared.contains("..Default::default()")
            && !backend_prepared.contains("singlematch: true")
            && !backend_prepared.contains("caseless: Some(")
            && !backend_prepared.contains("utf8: false"),
        "phase-1 SIMD scanner must keep the legacy all-caseless sharded cache profile"
    );
    assert!(
        phase2_hs.contains("singlematch: true")
            && phase2_hs.contains("caseless: Some(&caseless)")
            && phase2_hs.contains("shard_target: Some(usize::MAX)")
            && phase2_hs.contains("utf8: false"),
        "phase-2 HS prefilter must keep its distinct singlematch/per-pattern/one-shard byte-mode cache profile"
    );
}
