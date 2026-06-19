#[test]
fn regex_cache_sharding_uses_shared_scanner_hash_owner() {
    let source = include_str!("../../../src/compiler/compiler_compile.rs");
    let start = source
        .find("fn regex_cache_shard(pattern: &str)")
        .expect("regex_cache_shard present");
    let end = source[start..]
        .find("pub(crate) fn shared_regex_compile")
        .map(|offset| start + offset)
        .expect("regex_cache_shard boundary present");
    let body = &source[start..end];

    assert!(
        body.contains("crate::util_hash::hash_fast(pattern.as_bytes())")
            && !body.contains("DefaultHasher")
            && !body.contains("std::hash"),
        "regex cache sharding must reuse scanner util_hash instead of a second DefaultHasher cache-key primitive"
    );
}
