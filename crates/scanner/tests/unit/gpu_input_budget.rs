use crate::gpu_input_budget::*;

const MIB: usize = 1024 * 1024;

#[test]
fn sizing_bounds_are_the_floor_and_cap() {
    let (floor, cap) = gpu_batch_input_limit_bounds();
    assert_eq!(floor, 128 * MIB);
    assert_eq!(cap, 1024 * MIB);
    assert_eq!(floor, GPU_BATCH_INPUT_LIMIT_UNKNOWN);
    assert_eq!(cap, GPU_BATCH_INPUT_LIMIT_HIGH);
}

#[test]
fn override_clamps_into_sizing_bounds() {
    assert_eq!(clamp_gpu_batch_input_limit(1), 128 * MIB);
    assert_eq!(clamp_gpu_batch_input_limit(64 * MIB), 128 * MIB);
    assert_eq!(clamp_gpu_batch_input_limit(300 * MIB), 300 * MIB);
    assert_eq!(clamp_gpu_batch_input_limit(1024 * MIB), 1024 * MIB);
    assert_eq!(clamp_gpu_batch_input_limit(usize::MAX), 1024 * MIB);
}

#[test]
fn vram_table_reads_only_the_named_owners() {
    assert_eq!(
        gpu_batch_input_limit_for_vram_mb(Some(VRAM_MB_TIER_HIGH)),
        GPU_BATCH_INPUT_LIMIT_HIGH
    );
    assert_eq!(
        gpu_batch_input_limit_for_vram_mb(Some(VRAM_MB_TIER_HIGH - 1)),
        GPU_BATCH_INPUT_LIMIT_MID
    );
    assert_eq!(
        gpu_batch_input_limit_for_vram_mb(Some(VRAM_MB_TIER_MID)),
        GPU_BATCH_INPUT_LIMIT_MID
    );
    assert_eq!(
        gpu_batch_input_limit_for_vram_mb(Some(VRAM_MB_TIER_MID - 1)),
        GPU_BATCH_INPUT_LIMIT_LOW
    );
    assert_eq!(
        gpu_batch_input_limit_for_vram_mb(Some(VRAM_MB_TIER_LOW)),
        GPU_BATCH_INPUT_LIMIT_LOW
    );
    assert_eq!(
        gpu_batch_input_limit_for_vram_mb(Some(VRAM_MB_TIER_LOW - 1)),
        GPU_BATCH_INPUT_LIMIT_UNKNOWN
    );
    assert_eq!(
        gpu_batch_input_limit_for_vram_mb(Some(0)),
        GPU_BATCH_INPUT_LIMIT_UNKNOWN
    );
    assert_eq!(
        gpu_batch_input_limit_for_vram_mb(None),
        GPU_BATCH_INPUT_LIMIT_UNKNOWN
    );
}

#[test]
fn override_resolves_to_none_when_unset_and_clamped_when_set() {
    assert_eq!(gpu_batch_input_limit_override(), None);
    set_gpu_batch_input_limit(9 * 1024 * MIB);
    assert_eq!(gpu_batch_input_limit_override(), Some(1024 * MIB));
    set_gpu_batch_input_limit(200 * MIB);
    assert_eq!(gpu_batch_input_limit_override(), Some(200 * MIB));
    set_gpu_batch_input_limit(0);
    assert_eq!(gpu_batch_input_limit_override(), None);

    let adaptive = gpu_batch_input_limit();
    set_gpu_batch_input_limit(200 * MIB);
    assert_eq!(gpu_batch_input_limit(), 200 * MIB);
    set_gpu_batch_input_limit(0);
    assert_eq!(gpu_batch_input_limit(), adaptive);
}
