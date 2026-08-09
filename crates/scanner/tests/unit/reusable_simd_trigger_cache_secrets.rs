#[cfg(feature = "simd")]
#[test]
fn reusable_simd_trigger_cache_does_not_retain_source_payload_bytes() {
    use crate::engine::ReusableSimdTriggerCache;
    use keyhog_core::SensitiveString;

    let mut cache = ReusableSimdTriggerCache::default();
    let payload = SensitiveString::from("SECRET_KEY_PAYLOAD_1234567890");

    let computed = cache
        .get_or_compute(&payload, || Ok(Some(vec![1, 2, 3])))
        .expect("compute ok");
    assert!(computed.is_some());

    assert!(!cache.contains_payload_bytes());

    let hit = cache
        .get_or_compute(&payload, || panic!("should be cache hit"))
        .expect("hit ok");
    assert_eq!(hit, computed);

    cache.clear();

    let computed_after_clear = cache
        .get_or_compute(&payload, || Ok(Some(vec![4, 5, 6])))
        .expect("compute after clear ok");
    assert_ne!(computed_after_clear, computed);
}
