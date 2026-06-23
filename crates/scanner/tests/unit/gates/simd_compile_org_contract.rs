#[test]
fn hyperscan_compile_with_opts_delegates_compile_stages() {
    let source =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/simd/backend.rs"))
            .expect("simd backend source readable");

    for required in [
        "const MAX_HS_PATTERN_LEN: usize = 500;",
        "const BASE_PATTERN_COST: u64 = 16;",
        "const RETRY_THRESHOLD: usize = 100;",
        "const RETRY_DROP_DIVISOR: usize = 10;",
        "fn prepare_patterns(",
        "fn compile_cache_key(",
        "fn compile_shard_count(",
        "fn partition_patterns_lpt(",
        "fn compile_cached_shards(",
        "fn assemble_scanner_shards(",
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
            && partition_body.contains(".len()")
            && partition_body.contains(".then_with(|| hs_pats[a].id.cmp(&hs_pats[b].id))")
            && partition_body.contains(".then_with(|| a.cmp(&b))")
            && !partition_body.contains("sort_unstable_by_key"),
        "Hyperscan LPT partitioning must use deterministic tie-breakers so equal-length patterns do not churn shard cache keys"
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
