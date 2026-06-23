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
