//! Volume oracle matrix - independent reference vs production cpu_ref.
//! Legendary testing.volume - do NOT weaken to shape-only asserts.
#![forbid(unsafe_code)]

#![cfg(all(feature = "graph", feature = "cpu-parity"))]

use vyre_primitives::graph::scc_decompose;

fn bitset_words(node_count: u32) -> usize {
    vyre_primitives::bitset::bitset_words(node_count) as usize
}

fn next_u32(rng: &mut u64) -> u32 {
    *rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
    (*rng >> 32) as u32
}

fn generated_csr_frontier(seed: u64) -> (u32, Vec<u32>, Vec<u32>, Vec<u32>, Vec<u32>, u32) {
    let mut rng = seed;
    let node_count = 1 + next_u32(&mut rng) % 96;
    let words = bitset_words(node_count);
    let mut offsets = Vec::with_capacity(node_count as usize + 1);
    let mut targets = Vec::new();
    let mut masks = Vec::new();
    offsets.push(0);
    for _ in 0..node_count {
        let degree = next_u32(&mut rng) % 6;
        for _ in 0..degree {
            targets.push(next_u32(&mut rng) % node_count);
            masks.push(1u32 << (next_u32(&mut rng) % 5));
        }
        offsets.push(targets.len() as u32);
    }
    let mut frontier = vec![0u32; words];
    let start = next_u32(&mut rng) % node_count;
    frontier[(start / 32) as usize] |= 1u32 << (start % 32);
    let allow_mask = 0xFFFF_FFFFu32;
    (node_count, offsets, targets, masks, frontier, allow_mask)
}


fn oracle_scc(
    node_count: u32,
    forward: &[u32],
    backward: &[u32],
    component_in: &[u32],
    pivot: u32,
) -> Vec<u32> {
    let mut out = component_in.to_vec();
    for v in 0..node_count {
        let word = (v / 32) as usize;
        let bit = 1u32 << (v % 32);
        let fwd = word < forward.len() && forward[word] & bit != 0;
        let bwd = word < backward.len() && backward[word] & bit != 0;
        if fwd && bwd && out[v as usize] == u32::MAX {
            out[v as usize] = pivot;
        }
    }
    out
}

const CASES: usize = 16384;

#[test]
fn sweep_graph_scc_decompose_volume_oracle_matrix() {
    for case in 0..CASES {
        let seed = case as u64 ^ 0x5CCDEC0D;
        let (node_count, _, _, _, frontier, _) = generated_csr_frontier(seed);
        let words = bitset_words(node_count);
        let backward = frontier.clone();
        let component_in = vec![u32::MAX; node_count as usize];
        let pivot = (case % node_count as usize) as u32;
        let expected = oracle_scc(node_count, &frontier, &backward, &component_in, pivot);
        let actual = scc_decompose::cpu_ref(
            node_count, &frontier, &backward, &component_in, pivot,
        );
        assert_eq!(actual, expected, "Fix: scc_decompose volume case {case}");
    }
}
