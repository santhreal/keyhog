//! Gap test: GPU routing-profile tier table (pure, GPU-free).
//!
//! `gpu_routing_profiles()` returns one [`GpuRoutingProfile`] per GpuTier; the
//! array width is now the named `GPU_TIER_COUNT` (= 3: High, Mid, Low). Pin the
//! full table through real behavior: the count, the High/Mid/Low ordering, each
//! tier's min/solo byte and pattern-breakeven thresholds, and the adapter-name
//! classifier that routes a name to its tier profile.

use keyhog_scanner::hw_probe::{gpu_routing_profile, gpu_routing_profiles};

const MIB: u64 = 1024 * 1024;

#[test]
fn profiles_table_has_one_row_per_tier_in_order() {
    let profiles = gpu_routing_profiles();
    // Width is GPU_TIER_COUNT.
    assert_eq!(profiles.len(), 3);
    assert_eq!(profiles[0].tier, "high");
    assert_eq!(profiles[1].tier, "mid");
    assert_eq!(profiles[2].tier, "low");
}

#[test]
fn per_tier_thresholds_are_exact() {
    let profiles = gpu_routing_profiles();
    // High tier: lowest byte floors (fastest dispatch), 100-pattern breakeven.
    assert_eq!(profiles[0].min_bytes, 128 * MIB);
    assert_eq!(profiles[0].solo_bytes, 256 * MIB);
    assert_eq!(profiles[0].pattern_breakeven, 100);
    // Mid tier: middle min-bytes floor.
    assert_eq!(profiles[1].min_bytes, 256 * MIB);
    // Low/unknown tier: most conservative min-bytes floor.
    assert_eq!(profiles[2].min_bytes, 512 * MIB);
}

#[test]
fn adapter_name_routes_to_its_tier_profile() {
    assert_eq!(
        gpu_routing_profile(Some("NVIDIA GeForce RTX 4090")).tier,
        "high"
    );
    assert_eq!(gpu_routing_profile(Some("Apple M1 Max")).tier, "high");
    assert_eq!(
        gpu_routing_profile(Some("NVIDIA GeForce RTX 3080")).tier,
        "mid"
    );
    assert_eq!(gpu_routing_profile(Some("Intel Arc A770")).tier, "mid");
    assert_eq!(gpu_routing_profile(Some("Intel UHD Graphics")).tier, "low");
    // An absent adapter name is the most conservative (low) tier.
    assert_eq!(gpu_routing_profile(None).tier, "low");
}
