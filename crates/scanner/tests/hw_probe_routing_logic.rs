//! Unit coverage for the PURE hardware-routing decision logic (#177/#183).
//!
//! The existing `backend_parity_*` suite proves CPU and GPU produce identical
//! findings; it does NOT pin the routing *decision* functions themselves. These
//! functions are pure functions of their arguments with no runtime device
//! probing, so every assertion here is deterministic on any host, GPU or not.
//! They assert concrete values (Law 6), never just shape.

use keyhog_scanner::hw_probe::{gpu_routing_profile, gpu_routing_profiles, GpuRoutingProfile};

/// `gpu_routing_profiles()` returns exactly [High, Mid, Low] in that order.
fn profiles() -> [GpuRoutingProfile; 3] {
    gpu_routing_profiles()
}

#[test]
fn high_tier_adapters_classify_to_the_high_profile() {
    let high = profiles()[0];
    // Every current high-tier discrete must resolve to the SAME (High) profile as
    // the tier-array head (proving `classify_gpu_tier` routes them to High).
    for name in [
        "NVIDIA GeForce RTX 5090",
        "RTX 4090",
        "NVIDIA A100-SXM4-80GB",
        "NVIDIA H100 PCIe",
    ] {
        let p = gpu_routing_profile(Some(name));
        assert_eq!(
            p.tier, high.tier,
            "{name} must classify to the High tier ({}), got {}",
            high.tier, p.tier
        );
        assert_eq!(p.min_bytes, high.min_bytes, "{name} min_bytes mismatch");
    }
}

#[test]
fn no_adapter_classifies_to_the_low_profile() {
    let low = profiles()[2];
    let p = gpu_routing_profile(None);
    assert_eq!(
        p.tier, low.tier,
        "absent adapter must classify to the Low tier ({}), got {}",
        low.tier, p.tier
    );
    assert_eq!(p.min_bytes, low.min_bytes);
}

#[test]
fn classification_is_ascii_case_insensitive() {
    // `classify_gpu_tier` lowercases the name; upper/lower must be identical.
    let upper = gpu_routing_profile(Some("RTX 5090"));
    let lower = gpu_routing_profile(Some("rtx 5090"));
    assert_eq!(upper.tier, lower.tier);
    assert_eq!(upper.min_bytes, lower.min_bytes);
    assert_eq!(upper.solo_bytes, lower.solo_bytes);
    assert_eq!(upper.pattern_breakeven, lower.pattern_breakeven);
}

#[test]
fn tiers_are_distinct_and_all_thresholds_positive() {
    let [high, mid, low] = profiles();
    // Three genuinely different tiers, not aliases.
    assert_ne!(high.tier, mid.tier);
    assert_ne!(mid.tier, low.tier);
    assert_ne!(high.tier, low.tier);
    // Every threshold is a real positive bound (a zero would mean "GPU always on"
    // or "never solo" by accident).
    for p in [high, mid, low] {
        assert!(p.min_bytes > 0, "{}: min_bytes must be > 0", p.tier);
        assert!(p.solo_bytes > 0, "{}: solo_bytes must be > 0", p.tier);
        assert!(
            p.pattern_breakeven > 0,
            "{}: pattern_breakeven must be > 0",
            p.tier
        );
    }
}

#[test]
fn better_tiers_engage_the_gpu_no_later_than_worse_tiers() {
    // A faster GPU is worth engaging at an equal-or-smaller workload, so the
    // engage/solo byte thresholds must be monotonic non-increasing High→Low.
    let [high, mid, low] = profiles();
    assert!(
        high.min_bytes <= mid.min_bytes && mid.min_bytes <= low.min_bytes,
        "min_bytes must be non-increasing by tier quality: High={} Mid={} Low={}",
        high.min_bytes,
        mid.min_bytes,
        low.min_bytes
    );
    assert!(
        high.solo_bytes <= mid.solo_bytes && mid.solo_bytes <= low.solo_bytes,
        "solo_bytes must be non-increasing by tier quality: High={} Mid={} Low={}",
        high.solo_bytes,
        mid.solo_bytes,
        low.solo_bytes
    );
}

#[test]
fn solo_threshold_is_at_or_above_the_engage_threshold() {
    // The GPU cannot run SOLO before it is allowed to engage at all: for every
    // tier, solo_bytes >= min_bytes.
    for p in profiles() {
        assert!(
            p.solo_bytes >= p.min_bytes,
            "{}: solo_bytes ({}) must be >= min_bytes ({})",
            p.tier,
            p.solo_bytes,
            p.min_bytes
        );
    }
}

// NOTE: the `/proc/cpuinfo` + `/proc/meminfo` parse fns
// (`linux_physical_cores_from_cpuinfo` / `linux_total_memory_mb_from_meminfo`)
// are `pub(crate)` and only re-exported through the `#[cfg(test)]` `hw_probe::
// testing` facade, so they are reachable from the lib's own unit tests but NOT
// from this external integration crate. Their coverage lives with the lib.
