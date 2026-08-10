use crate::engine::*;

#[test]
fn canonical_cap_is_one_million() {
    assert_eq!(keyhog_scanner::engine::MAX_INNER_LOOP_ITERS, 1_000_000);
}

#[test]
fn cap_is_whole_multiple_of_deadline_cadence() {
    assert_eq!(keyhog_scanner::deadline::HOT_LOOP_DEADLINE_CADENCE, 64);
    assert_eq!(
        keyhog_scanner::engine::MAX_INNER_LOOP_ITERS
            % keyhog_scanner::deadline::HOT_LOOP_DEADLINE_CADENCE,
        0
    );
    assert_eq!(
        keyhog_scanner::engine::MAX_INNER_LOOP_ITERS
            / keyhog_scanner::deadline::HOT_LOOP_DEADLINE_CADENCE,
        15_625
    );
}

#[test]
fn bigram_bloom_min_chunk_bytes_is_sixty_four() {
    assert_eq!(keyhog_scanner::engine::BIGRAM_BLOOM_MIN_CHUNK_BYTES, 64);
}

#[test]
fn boundary_seam_cap_matches_window_overlap() {
    assert_eq!(
        keyhog_scanner::engine::MAX_BOUNDARY_SEAM_BYTES,
        keyhog_scanner::types::WINDOW_OVERLAP_BYTES
    );
    assert_eq!(keyhog_scanner::engine::MAX_BOUNDARY_SEAM_BYTES, 128 * 1024);
}
