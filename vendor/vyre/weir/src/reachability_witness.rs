//! Reachability witness — bridge between the Tier-3 ProgramGraph
//! forward-reach primitive (`vyre_primitives::ifds_reach_step` driven
//! to fixpoint by the caller) and surgec's proof-bundle assembly.
//!
//! ## What this module produces
//!
//! Given:
//! - `source_reach`: a per-node reachability bitmask whose bit `n` is
//!   set iff the *specific source named in the `PathSeed`* reaches
//!   node `n` along some IFDS-eligible path. Per-source masks are
//!   required so that a multi-source taint analysis cannot produce a
//!   witness that mixes paths originating from a different source
//!   (audit 2026-04-27 finding 3).
//! - `sanitizer_mask`: a per-node bitmask whose bit `n` is set iff
//!   node `n` is a sanitizer for this rule. The walker rejects any
//!   sanitizer-tagged predecessor so a witness that crosses a
//!   sanitizer is never emitted (audit 2026-04-27 finding 2).
//! - the program-graph CSR (edge_offsets / edge_targets /
//!   edge_kind_mask).
//! - a [`PathSeed`] naming the source and sink stmt-ids.
//!
//! [`extract_path`] walks the CFG **backward** from the sink,
//! greedily choosing a reached, non-sanitized predecessor at each
//! step until the source is hit. The resulting ordered statement
//! list is the path proven by the upstream forward-reach analysis.
//!
//! This is a CPU-side function — paths are short (typically <50
//! statements after slicing), so parallelism is not meaningful here.
//! The reachability shader stays unchanged; we read its output
//! buffer + the CSR to reconstruct the path.
//!
//! ## Soundness
//!
//! The walk is greedy: it selects ANY reached, non-sanitized
//! predecessor at each step. That gives one valid path, not
//! necessarily the shortest. For surgec's proof-bundling needs
//! (showing the user the chain of statements taint flows through),
//! any valid path is sufficient — the existence of A path is what
//! the proof asserts.
//!
//! ## Scope of the upstream analysis
//!
//! The caller's bitmasks must come from the Tier-3 forward-reach
//! primitive (`vyre_primitives::graph::ifds_reach_step`). The full
//! exploded-supergraph IFDS solver in `weir::ifds_gpu` operates on
//! `(proc, block, fact)` triple ids, which are disjoint from the
//! statement ids this module consumes. Bridging the exploded
//! namespace requires a separate decoder (TODO: not yet shipped); do
//! not feed exploded-supergraph reachability buffers here without
//! first decoding them back to statement ids (audit finding 1).
//!
//! For a `MayUnder` mode that returns the shortest path or all
//! paths, see `vyre_primitives::graph::shortest_path` /
//! `path_reconstruct` — those compose on top of `extract_path`'s
//! output if a rule needs more than one witness.

use vyre_primitives::predicate::edge_kind;

/// Source-and-sink seed for path extraction. Caller (surgec) supplies
/// the file + byte offsets it identified from rule firing, and we
/// look them up against the CSR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSeed {
    /// Repository-relative file containing the source.
    pub source_file: String,
    /// Source stmt-id (index into pg_nodes).
    pub source_node: u32,
    /// Repository-relative file containing the sink.
    pub sink_file: String,
    /// Sink stmt-id.
    pub sink_node: u32,
}

/// One statement on an extracted path. Mirrors what surgec's
/// `proof::PathStatement` carries; this type lives in weir so the
/// witness backends can depend on weir without depending on surgec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedStatement {
    /// Source-language adapter id (e.g. `"c-c11"`).
    pub adapter: String,
    /// Brief human-readable description (e.g.
    /// `"call to recv at offset 1142"`).
    pub description: String,
    /// Repository-relative file.
    pub file: String,
    /// Statement node id (index into pg_nodes).
    pub node_id: u32,
    /// Byte range start (inclusive).
    pub byte_start: u32,
    /// Byte range end (exclusive).
    pub byte_end: u32,
}

/// The output of `extract_path` — the ordered statement list a path
/// traversed, source → sink.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExtractedPath {
    /// Path statements in source-to-sink order.
    pub statements: Vec<ExtractedStatement>,
}

/// Distinguishable failure modes for [`extract_path`]. The launch's
/// proof-assembly code maps each variant to a different finding-class
/// outcome; collapsing every error into `None` (the prior shape) hid
/// the depth-overrun case from the caller (audit 2026-04-27
/// finding 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    /// The IFDS analysis did not reach one of the endpoints; no path
    /// exists. Caller should keep the finding at Class 3 (heuristic).
    NoPath,
    /// A reached, non-sanitized predecessor existed at every step but
    /// the chain exceeded `MAX_PATH_DEPTH` before reaching the
    /// source. The partial chain (sink-first, length =
    /// `MAX_PATH_DEPTH`) is returned for diagnostics. Callers may
    /// fall back to a shortest-path algorithm or downgrade the
    /// finding.
    DepthExceeded {
        /// Sink-first list of statement ids walked before bailing.
        partial_chain: Vec<u32>,
    },
    /// `seed.source_node` or `seed.sink_node` is out of bounds for
    /// the supplied `pg_node_attrs` slice. Returned instead of
    /// panicking on `visited[current]` (audit finding 5).
    NodeOutOfBounds {
        /// The offending node id.
        node: u32,
        /// The valid range upper bound.
        node_count: u32,
    },
}

/// Mask of edge kinds eligible for IFDS-style path reconstruction.
/// The kinds that propagate taint along the dataflow super-graph:
/// dataflow assignment, call args, returns, phi, alias, mem store /
/// load, mut ref. Excludes DOMINANCE and CONTROL because those don't
/// transfer data.
const IFDS_PATH_EDGE_MASK: u32 = edge_kind::ASSIGNMENT
    | edge_kind::CALL_ARG
    | edge_kind::RETURN
    | edge_kind::PHI
    | edge_kind::ALIAS
    | edge_kind::MEM_STORE
    | edge_kind::MEM_LOAD
    | edge_kind::MUT_REF;

/// Maximum walk depth — prevents pathological CSRs from running the
/// reconstruction unbounded. Real source-to-sink paths in launch
/// fixtures are <50 statements; 1024 is generous.
const MAX_PATH_DEPTH: usize = 1024;

/// Test bit `i` in a packed u32 bitmask.
fn bit_is_set(bitmask: &[u32], i: u32) -> bool {
    let word = (i / 32) as usize;
    let bit = 1u32 << (i % 32);
    bitmask.get(word).is_some_and(|value| (*value & bit) != 0)
}

/// Reconstruct a source→sink path by walking the CSR backward from
/// `seed.sink_node`, greedily choosing a *source-reached*,
/// *non-sanitized* predecessor at each step until `seed.source_node`
/// is hit.
///
/// `source_reach` MUST be a per-source reachability mask: bit `n` is
/// set iff the *specific source named in the `PathSeed`* reaches
/// node `n` along an IFDS-eligible path. Aggregate-over-all-sources
/// masks must NOT be passed here — they admit witnesses that
/// originate from a different source than the seed (audit 2026-04-27
/// finding 3).
///
/// `sanitizer_mask` is a per-node bitmask whose bit `n` is set iff
/// node `n` is a sanitizer for this rule. The walker rejects any
/// sanitizer-tagged predecessor (audit finding 2). Pass an empty
/// slice (`&[]`) iff the rule has no sanitizers.
///
/// `pg_node_attrs` is a slice of `(byte_start, byte_end, file_idx)`
/// tuples — one per node — that surgec's pipeline emits alongside
/// the CSR. `file_table` maps `file_idx` to a repository-relative
/// path. `adapter` is the language-adapter id (e.g. `"c-c11"`).
/// `descriptions` is per-node short text.
///
/// Returns:
/// - `Ok(path)` when source is reached from sink along an
///   IFDS-eligible chain that does not cross any sanitizer.
/// - `Err(PathError::NoPath)` when no such path exists.
/// - `Err(PathError::DepthExceeded { partial_chain })` when the
///   chain exceeded `MAX_PATH_DEPTH` (audit finding 4).
/// - `Err(PathError::NodeOutOfBounds { .. })` when the seed names a
///   node id that is not present in `pg_node_attrs` (audit
///   finding 5).
#[allow(clippy::too_many_arguments)]
pub fn extract_path(
    seed: &PathSeed,
    source_reach: &[u32],
    sanitizer_mask: &[u32],
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    pg_node_attrs: &[NodeAttr],
    file_table: &[String],
    descriptions: &[String],
    adapter: &str,
) -> Result<ExtractedPath, PathError> {
    let node_count = pg_node_attrs.len() as u32;
    // Bound-check the seed BEFORE indexing into visited/attrs (audit
    // finding 5 — DoS via OOB sink_node).
    if seed.source_node >= node_count {
        return Err(PathError::NodeOutOfBounds {
            node: seed.source_node,
            node_count,
        });
    }
    if seed.sink_node >= node_count {
        return Err(PathError::NodeOutOfBounds {
            node: seed.sink_node,
            node_count,
        });
    }

    if seed.source_node == seed.sink_node {
        // Trivial path of length 1. Sanitizer check still applies:
        // if the source itself is tagged a sanitizer the witness is
        // unsound.
        if bit_is_set(sanitizer_mask, seed.source_node) {
            return Err(PathError::NoPath);
        }
        let stmt = build_statement(
            seed.source_node,
            pg_node_attrs,
            file_table,
            descriptions,
            adapter,
        )
        .ok_or(PathError::NodeOutOfBounds {
            node: seed.source_node,
            node_count,
        })?;
        return Ok(ExtractedPath {
            statements: vec![stmt],
        });
    }

    if !bit_is_set(source_reach, seed.sink_node) || !bit_is_set(source_reach, seed.source_node) {
        // The seeded source did not reach the seeded sink.
        return Err(PathError::NoPath);
    }
    // The endpoints themselves cannot be sanitizers — that would
    // mean the proof crosses a sanitizer at iteration 0.
    if bit_is_set(sanitizer_mask, seed.sink_node) || bit_is_set(sanitizer_mask, seed.source_node) {
        return Err(PathError::NoPath);
    }

    let mut visited = vec![false; pg_node_attrs.len()];
    let mut chain: Vec<u32> = Vec::new();
    let mut current = seed.sink_node;
    chain.push(current);
    visited[current as usize] = true;

    for _ in 0..MAX_PATH_DEPTH {
        if current == seed.source_node {
            break;
        }
        let Some(pred) = find_reached_predecessor(
            current,
            source_reach,
            sanitizer_mask,
            edge_offsets,
            edge_targets,
            edge_kind_mask,
            &visited,
        ) else {
            return Err(PathError::NoPath);
        };
        chain.push(pred);
        visited[pred as usize] = true;
        current = pred;
    }

    if current != seed.source_node {
        // Hit the depth limit before reaching the source. Hand the
        // partial chain back so the caller can attempt a shortest-
        // path fallback or downgrade the finding rather than
        // silently treating it as 'no path' (audit finding 4).
        return Err(PathError::DepthExceeded {
            partial_chain: chain,
        });
    }

    // chain is sink-first; flip to source-first.
    chain.reverse();
    let statements: Vec<ExtractedStatement> = chain
        .into_iter()
        .filter_map(|n| build_statement(n, pg_node_attrs, file_table, descriptions, adapter))
        .collect();
    Ok(ExtractedPath { statements })
}

/// Find any unvisited node `pred` such that there's an outgoing
/// IFDS-eligible edge from `pred` to `current` AND `pred` is
/// reached by the seeded source's reachability mask AND `pred` is
/// NOT a sanitizer. Returns `None` when no such pred exists.
fn find_reached_predecessor(
    current: u32,
    source_reach: &[u32],
    sanitizer_mask: &[u32],
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    visited: &[bool],
) -> Option<u32> {
    let node_count = (edge_offsets.len().saturating_sub(1)) as u32;
    for pred in 0..node_count {
        if visited.get(pred as usize).copied().unwrap_or(false) {
            continue;
        }
        if !bit_is_set(source_reach, pred) {
            continue;
        }
        if bit_is_set(sanitizer_mask, pred) {
            // A sanitizer-tagged predecessor would make the witness
            // cross a sanitizer; reject (audit finding 2).
            continue;
        }
        let start = edge_offsets[pred as usize] as usize;
        let end = edge_offsets[pred as usize + 1] as usize;
        for e in start..end {
            let dst = edge_targets.get(e).copied()?;
            if dst != current {
                continue;
            }
            let mask = edge_kind_mask.get(e).copied().unwrap_or(0);
            if mask & IFDS_PATH_EDGE_MASK != 0 {
                return Some(pred);
            }
        }
    }
    None
}

/// Per-node byte-range and file-index attributes that surgec's
/// pipeline emits alongside the CSR. Lives in this module because
/// path reconstruction is the consumer of these attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeAttr {
    /// Byte range start (inclusive).
    pub byte_start: u32,
    /// Byte range end (exclusive).
    pub byte_end: u32,
    /// Index into the file table.
    pub file_idx: u32,
}

fn build_statement(
    node_id: u32,
    pg_node_attrs: &[NodeAttr],
    file_table: &[String],
    descriptions: &[String],
    adapter: &str,
) -> Option<ExtractedStatement> {
    let attr = pg_node_attrs.get(node_id as usize)?;
    let file = file_table
        .get(attr.file_idx as usize)
        .cloned()
        .unwrap_or_else(|| String::from("<unknown>"));
    let description = descriptions
        .get(node_id as usize)
        .cloned()
        .unwrap_or_else(|| format!("node {node_id}"));
    Some(ExtractedStatement {
        adapter: adapter.to_string(),
        description,
        file,
        node_id,
        byte_start: attr.byte_start,
        byte_end: attr.byte_end,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_attrs(n: usize) -> Vec<NodeAttr> {
        (0..n as u32)
            .map(|i| NodeAttr {
                byte_start: i * 10,
                byte_end: (i + 1) * 10,
                file_idx: 0,
            })
            .collect()
    }

    #[test]
    fn trivial_self_path() {
        let seed = PathSeed {
            source_file: "a.c".to_string(),
            source_node: 3,
            sink_file: "a.c".to_string(),
            sink_node: 3,
        };
        let attrs = dummy_attrs(5);
        let files = vec!["a.c".to_string()];
        let descs: Vec<String> = (0..5).map(|i| format!("stmt{i}")).collect();
        let path = extract_path(
            &seed,
            &[0xFFFF],
            &[],
            &[0; 6],
            &[],
            &[],
            &attrs,
            &files,
            &descs,
            "c-c11",
        )
        .expect("trivial path must reconstruct");
        assert_eq!(path.statements.len(), 1);
        assert_eq!(path.statements[0].node_id, 3);
    }

    #[test]
    fn no_path_when_endpoints_not_reached() {
        let seed = PathSeed {
            source_file: "a.c".to_string(),
            source_node: 0,
            sink_file: "a.c".to_string(),
            sink_node: 3,
        };
        let attrs = dummy_attrs(4);
        let files = vec!["a.c".to_string()];
        let descs: Vec<String> = (0..4).map(|i| format!("stmt{i}")).collect();
        // Reachability bitmask has bit 0 but not bit 3.
        let err = extract_path(
            &seed,
            &[0b0001],
            &[],
            &[0, 1, 2, 3, 3],
            &[1, 2, 3],
            &[edge_kind::ASSIGNMENT; 3],
            &attrs,
            &files,
            &descs,
            "c-c11",
        )
        .expect_err("no path expected");
        assert_eq!(err, PathError::NoPath);
    }

    #[test]
    fn linear_chain_reconstructs() {
        // Graph: 0 → 1 → 2 → 3 (all assignment edges)
        let seed = PathSeed {
            source_file: "a.c".to_string(),
            source_node: 0,
            sink_file: "a.c".to_string(),
            sink_node: 3,
        };
        let attrs = dummy_attrs(4);
        let files = vec!["a.c".to_string()];
        let descs: Vec<String> = (0..4).map(|i| format!("stmt{i}")).collect();
        let edge_offsets = vec![0, 1, 2, 3, 3];
        let edge_targets = vec![1u32, 2, 3];
        let edge_kind_mask = vec![edge_kind::ASSIGNMENT; 3];
        let source_reach = vec![0b1111];
        let path = extract_path(
            &seed,
            &source_reach,
            &[],
            &edge_offsets,
            &edge_targets,
            &edge_kind_mask,
            &attrs,
            &files,
            &descs,
            "c-c11",
        )
        .expect("linear-chain path must reconstruct");
        let ids: Vec<u32> = path.statements.iter().map(|s| s.node_id).collect();
        assert_eq!(ids, vec![0, 1, 2, 3]);
        assert_eq!(path.statements[0].file, "a.c");
        assert_eq!(path.statements[0].adapter, "c-c11");
    }

    #[test]
    fn ignores_non_ifds_edges() {
        // Graph: 0 →[CONTROL] 1 →[ASSIGNMENT] 2.
        // CONTROL edges shouldn't propagate IFDS taint, so the path
        // walker shouldn't follow 1 ← 0 even though both are reached.
        let seed = PathSeed {
            source_file: "a.c".to_string(),
            source_node: 0,
            sink_file: "a.c".to_string(),
            sink_node: 2,
        };
        let attrs = dummy_attrs(3);
        let files = vec!["a.c".to_string()];
        let descs: Vec<String> = (0..3).map(|i| format!("stmt{i}")).collect();
        let edge_offsets = vec![0, 1, 2, 2];
        let edge_targets = vec![1u32, 2];
        let edge_kind_mask = vec![edge_kind::CONTROL, edge_kind::ASSIGNMENT];
        let source_reach = vec![0b111];
        let err = extract_path(
            &seed,
            &source_reach,
            &[],
            &edge_offsets,
            &edge_targets,
            &edge_kind_mask,
            &attrs,
            &files,
            &descs,
            "c-c11",
        )
        .expect_err("no IFDS-eligible predecessor of 1 → no path");
        assert_eq!(err, PathError::NoPath);
    }

    /// AUDIT 2026-04-27 finding 2: the walker must reject any
    /// predecessor whose bit is set in the sanitizer mask. Without
    /// this, the witness silently crosses a sanitizer.
    #[test]
    fn rejects_sanitizer_on_path() {
        // Graph: 0 → 1 → 2 → 3 (all assignment, all reached).
        // Node 1 is a sanitizer; the walker must refuse to use it
        // as a predecessor → no path source(0)→sink(3).
        let seed = PathSeed {
            source_file: "a.c".to_string(),
            source_node: 0,
            sink_file: "a.c".to_string(),
            sink_node: 3,
        };
        let attrs = dummy_attrs(4);
        let files = vec!["a.c".to_string()];
        let descs: Vec<String> = (0..4).map(|i| format!("stmt{i}")).collect();
        let edge_offsets = vec![0, 1, 2, 3, 3];
        let edge_targets = vec![1u32, 2, 3];
        let edge_kind_mask = vec![edge_kind::ASSIGNMENT; 3];
        let source_reach = vec![0b1111];
        let sanitizer_mask = vec![0b0010]; // bit 1 = sanitizer
        let err = extract_path(
            &seed,
            &source_reach,
            &sanitizer_mask,
            &edge_offsets,
            &edge_targets,
            &edge_kind_mask,
            &attrs,
            &files,
            &descs,
            "c-c11",
        )
        .expect_err("witness must not cross sanitizer");
        assert_eq!(err, PathError::NoPath);
    }

    /// Negative twin of `rejects_sanitizer_on_path`: when the
    /// sanitizer is set on a node OFF the path, reconstruction
    /// proceeds normally.
    #[test]
    fn sanitizer_off_path_does_not_block_reconstruction() {
        // Graph: 0 → 1 → 2; node 5 is a sanitizer but is not on
        // the source→sink path. Witness must still reconstruct.
        let seed = PathSeed {
            source_file: "a.c".to_string(),
            source_node: 0,
            sink_file: "a.c".to_string(),
            sink_node: 2,
        };
        let attrs = dummy_attrs(6);
        let files = vec!["a.c".to_string()];
        let descs: Vec<String> = (0..6).map(|i| format!("stmt{i}")).collect();
        let edge_offsets = vec![0, 1, 2, 2, 2, 2, 2];
        let edge_targets = vec![1u32, 2];
        let edge_kind_mask = vec![edge_kind::ASSIGNMENT; 2];
        let source_reach = vec![0b111111];
        let sanitizer_mask = vec![0b100000]; // bit 5 = sanitizer
        let path = extract_path(
            &seed,
            &source_reach,
            &sanitizer_mask,
            &edge_offsets,
            &edge_targets,
            &edge_kind_mask,
            &attrs,
            &files,
            &descs,
            "c-c11",
        )
        .expect("off-path sanitizer must not block reconstruction");
        assert_eq!(
            path.statements
                .iter()
                .map(|s| s.node_id)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }

    /// AUDIT 2026-04-27 finding 4: depth overrun must surface a
    /// `DepthExceeded` variant carrying the partial chain so the
    /// caller can distinguish it from the genuine `NoPath` case.
    #[test]
    fn depth_exceeded_returns_partial_chain() {
        // A long linear chain longer than MAX_PATH_DEPTH. The walker
        // must hit the limit and return DepthExceeded instead of
        // silently failing.
        let n = MAX_PATH_DEPTH + 50;
        let seed = PathSeed {
            source_file: "a.c".to_string(),
            source_node: 0,
            sink_file: "a.c".to_string(),
            sink_node: (n as u32) - 1,
        };
        let attrs = dummy_attrs(n);
        let files = vec!["a.c".to_string()];
        let descs: Vec<String> = (0..n).map(|i| format!("stmt{i}")).collect();
        // edge_offsets[i] = i so each node has one outgoing edge to
        // i+1; final node has no outgoing edge.
        let mut edge_offsets: Vec<u32> = (0..=n as u32).collect();
        // Last entry must equal edge count (n-1). Patch.
        if let Some(last) = edge_offsets.last_mut() {
            *last = (n - 1) as u32;
        }
        // Last-but-one too: nodes [0..n-1] each have 1 outgoing edge.
        let edge_targets: Vec<u32> = (1..n as u32).collect();
        let edge_kind_mask: Vec<u32> = vec![edge_kind::ASSIGNMENT; n - 1];
        // Reach mask: every node reached.
        let words = n.div_ceil(32);
        let source_reach = vec![u32::MAX; words];
        let err = extract_path(
            &seed,
            &source_reach,
            &[],
            &edge_offsets,
            &edge_targets,
            &edge_kind_mask,
            &attrs,
            &files,
            &descs,
            "c-c11",
        )
        .expect_err("path longer than MAX_PATH_DEPTH must surface");
        match err {
            PathError::DepthExceeded { partial_chain } => {
                // Walker took exactly MAX_PATH_DEPTH steps after the
                // initial sink push; the partial chain is sink-first
                // and at most MAX_PATH_DEPTH + 1 entries long.
                assert!(partial_chain.len() >= MAX_PATH_DEPTH);
                assert_eq!(partial_chain[0], (n as u32) - 1);
            }
            other => panic!("expected DepthExceeded, got {other:?}"),
        }
    }

    /// AUDIT 2026-04-27 finding 5: a seed naming a node that's out
    /// of bounds for `pg_node_attrs` must surface as
    /// `NodeOutOfBounds`, not panic on `visited[current]`.
    #[test]
    fn out_of_bounds_seed_surfaces_as_error() {
        let seed = PathSeed {
            source_file: "a.c".to_string(),
            source_node: 0,
            sink_file: "a.c".to_string(),
            sink_node: 9999, // way past pg_node_attrs.len()
        };
        let attrs = dummy_attrs(4);
        let files = vec!["a.c".to_string()];
        let descs: Vec<String> = (0..4).map(|i| format!("stmt{i}")).collect();
        let err = extract_path(
            &seed,
            &[u32::MAX; 4],
            &[],
            &[0, 1, 2, 3, 3],
            &[1, 2, 3],
            &[edge_kind::ASSIGNMENT; 3],
            &attrs,
            &files,
            &descs,
            "c-c11",
        )
        .expect_err("OOB seed must surface as error, not panic");
        match err {
            PathError::NodeOutOfBounds { node, node_count } => {
                assert_eq!(node, 9999);
                assert_eq!(node_count, 4);
            }
            other => panic!("expected NodeOutOfBounds, got {other:?}"),
        }
    }

    /// AUDIT 2026-04-27 finding 3: per-source reachability masks.
    /// When `source_reach` represents source A but the seed names
    /// source A, the walker must follow A's chain — not the
    /// aggregate-over-all-sources chain that another source B might
    /// admit. Demonstration: graph has two sources reaching a
    /// shared sink via different intermediate paths; the walker
    /// must follow the seeded source's mask, not an aggregate.
    #[test]
    fn per_source_mask_drives_path_choice() {
        // Graph: 0 → 2 → 4 (source A's chain)
        //         1 → 3 → 4 (source B's chain)
        let attrs = dummy_attrs(5);
        let files = vec!["a.c".to_string()];
        let descs: Vec<String> = (0..5).map(|i| format!("stmt{i}")).collect();
        let edge_offsets = vec![0, 1, 2, 3, 4, 4];
        let edge_targets = vec![2u32, 3, 4, 4];
        let edge_kind_mask = vec![edge_kind::ASSIGNMENT; 4];

        // Source A's mask: reaches 0, 2, 4 (NOT 1, NOT 3).
        let source_a_reach = vec![0b10101];
        let seed_a = PathSeed {
            source_file: "a.c".to_string(),
            source_node: 0,
            sink_file: "a.c".to_string(),
            sink_node: 4,
        };
        let path_a = extract_path(
            &seed_a,
            &source_a_reach,
            &[],
            &edge_offsets,
            &edge_targets,
            &edge_kind_mask,
            &attrs,
            &files,
            &descs,
            "c-c11",
        )
        .expect("source A's path must reconstruct");
        assert_eq!(
            path_a
                .statements
                .iter()
                .map(|s| s.node_id)
                .collect::<Vec<_>>(),
            vec![0, 2, 4]
        );

        // If we (incorrectly) handed the AGGREGATE mask to the
        // walker AND seeded with source A, the walker might pick
        // node 1 or 3 as a predecessor of 4 — which is source B's
        // chain. The per-source mask above prevents that.
    }
}
