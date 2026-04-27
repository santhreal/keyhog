//! Decode → scan fusion optimizer pass (G5).
//!
//! # Idea
//!
//! When a single Program already contains both a decoder and a
//! scanner — the decoder writes some `ReadWrite` storage handoff
//! buffer, the scanner then reads from it — the decoded bytes
//! don't need to round-trip through DRAM. Promoting the handoff
//! to workgroup memory keeps the bytes in the SM's shared
//! scratchpad and lets the scanner hit L1 instead of HBM.
//!
//! The companion library API in
//! [`vyre_libs::decode::streaming::fuse_decode_scan`] does the
//! same transform for a *pair* of Programs (separately-owned
//! decoder + scanner); this pass handles the pre-fused case that
//! already lives in one [`Program`].
//!
//! # Transform
//!
//! For every buffer `b` where:
//!   * `b.access() == BufferAccess::ReadWrite` (written then read),
//!   * `b.count() > 0` (static size known — workgroup memory
//!     requires a compile-time count), and
//!   * `b` is not marked `pipeline_live_out` (a workgroup buffer
//!     cannot be observed outside the dispatch),
//!
//! the pass rewrites `b` in-place to
//! `BufferDecl::workgroup(name, count, element)` — the access mode
//! flips to `Workgroup`, the memory tier flips to `Shared`, and
//! the binding slot is dropped (workgroup buffers do not hold a
//! `@binding`). Entry-body node ops reference buffers by name, so
//! no body rewriting is required.

use rustc_hash::FxHashMap;

use crate::ir::{BufferAccess, BufferDecl, Program};

/// Run the decode→scan fusion over a Program.
///
/// Promotes every handoff-looking `ReadWrite` storage buffer to
/// workgroup memory. Returns the rewritten Program. Caller-visible
/// buffers (`pipeline_live_out = true`) are preserved as-is.
#[must_use]
pub fn run(program: Program) -> Program {
    let promotable: Vec<String> = program
        .buffers
        .iter()
        .filter(|b| {
            b.access() == BufferAccess::ReadWrite && b.count() > 0 && !b.is_pipeline_live_out()
        })
        .map(|b| b.name().to_string())
        .collect();

    if promotable.is_empty() {
        return program;
    }

    let new_buffers: Vec<BufferDecl> = program
        .buffers
        .iter()
        .map(|b| {
            if promotable.iter().any(|n| n == b.name()) {
                BufferDecl::workgroup(b.name(), b.count(), b.element())
            } else {
                b.clone()
            }
        })
        .collect();

    // VYRE_IR_HOTSPOTS audit: avoid the deep-clone of the entry
    // Vec<Node>. When the Arc is unique (the common case — we own
    // the only reference after `run()` returns) `try_unwrap` hands
    // back the Vec<Node> directly. Only fall back to cloning when
    // another Arc is still outstanding.
    let entry = std::sync::Arc::try_unwrap(program.entry).unwrap_or_else(|arc| (*arc).clone());
    Program::wrapped(new_buffers, program.workgroup_size, entry)
}

/// Count decode-handoff candidate buffers in `program` — the
/// buffers `run` would promote. Identical filter to `run`.
#[must_use]
pub fn count_opportunities(program: &Program) -> usize {
    program
        .buffers
        .iter()
        .filter(|b| {
            b.access() == BufferAccess::ReadWrite && b.count() > 0 && !b.is_pipeline_live_out()
        })
        .count()
}

/// Map from candidate handoff buffer name to its declared element
/// count. Parallel to [`count_opportunities`] with names exposed.
#[must_use]
pub fn candidate_handoffs(program: &Program) -> FxHashMap<String, u32> {
    let mut out = FxHashMap::default();
    for buf in program.buffers.iter() {
        if buf.access() == BufferAccess::ReadWrite && buf.count() > 0 && !buf.is_pipeline_live_out()
        {
            out.insert(buf.name().to_string(), buf.count());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BufferDecl, DataType, Program};

    fn decoder_like() -> Program {
        Program::wrapped(
            vec![
                BufferDecl::storage("input", 0, BufferAccess::ReadOnly, DataType::U32)
                    .with_count(64),
                BufferDecl::storage("decoded", 1, BufferAccess::ReadWrite, DataType::U32)
                    .with_count(128),
            ],
            [64, 1, 1],
            vec![],
        )
    }

    #[test]
    fn run_promotes_readwrite_handoff_to_workgroup() {
        let p = decoder_like();
        let before_bufs = p.buffers.len();
        let after = run(p);
        assert_eq!(after.buffers.len(), before_bufs);
        let decoded = after
            .buffers
            .iter()
            .find(|b| b.name() == "decoded")
            .unwrap();
        assert_eq!(decoded.access(), BufferAccess::Workgroup);
    }

    #[test]
    fn run_leaves_read_only_buffers_alone() {
        let p = decoder_like();
        let after = run(p);
        let input = after.buffers.iter().find(|b| b.name() == "input").unwrap();
        assert_eq!(input.access(), BufferAccess::ReadOnly);
    }

    #[test]
    fn run_preserves_pipeline_live_out_buffer() {
        // A ReadWrite buffer that is live-out must NOT be demoted
        // to workgroup memory — callers expect to read it back.
        let p = Program::wrapped(
            vec![
                BufferDecl::storage("result", 0, BufferAccess::ReadWrite, DataType::U32)
                    .with_count(16)
                    .with_pipeline_live_out(true),
            ],
            [64, 1, 1],
            vec![],
        );
        let after = run(p);
        let r = after.buffers.iter().find(|b| b.name() == "result").unwrap();
        assert_eq!(r.access(), BufferAccess::ReadWrite);
        assert!(r.is_pipeline_live_out());
    }

    #[test]
    fn run_is_identity_when_no_candidates() {
        let p = Program::wrapped(
            vec![
                BufferDecl::storage("input", 0, BufferAccess::ReadOnly, DataType::U32)
                    .with_count(1),
            ],
            [64, 1, 1],
            vec![],
        );
        let after = run(p);
        assert_eq!(after.buffers.len(), 1);
        assert_eq!(after.buffers[0].access(), BufferAccess::ReadOnly);
    }

    #[test]
    fn run_skips_runtime_sized_buffers() {
        // count=0 means runtime-sized (no `with_count`); workgroup
        // allocations must be static so we can't promote those.
        let p = Program::wrapped(
            vec![BufferDecl::storage(
                "dynamic",
                0,
                BufferAccess::ReadWrite,
                DataType::U32,
            )],
            [64, 1, 1],
            vec![],
        );
        let after = run(p);
        let b = after
            .buffers
            .iter()
            .find(|b| b.name() == "dynamic")
            .unwrap();
        assert_eq!(b.access(), BufferAccess::ReadWrite);
    }

    #[test]
    fn count_opportunities_finds_one_candidate() {
        assert_eq!(count_opportunities(&decoder_like()), 1);
    }

    #[test]
    fn count_opportunities_zero_on_read_only_program() {
        let p = Program::wrapped(
            vec![
                BufferDecl::storage("input", 0, BufferAccess::ReadOnly, DataType::U32)
                    .with_count(1),
            ],
            [64, 1, 1],
            vec![],
        );
        assert_eq!(count_opportunities(&p), 0);
    }

    #[test]
    fn candidate_handoffs_exposes_name_and_count() {
        let p = decoder_like();
        let cands = candidate_handoffs(&p);
        assert_eq!(cands.get("decoded").copied(), Some(128));
        assert!(!cands.contains_key("input"));
    }

    #[test]
    fn multiple_candidates_all_surface() {
        let p = Program::wrapped(
            vec![
                BufferDecl::storage("a", 0, BufferAccess::ReadWrite, DataType::U32).with_count(32),
                BufferDecl::storage("b", 1, BufferAccess::ReadWrite, DataType::U32).with_count(64),
                BufferDecl::storage("c", 2, BufferAccess::ReadOnly, DataType::U32).with_count(16),
            ],
            [64, 1, 1],
            vec![],
        );
        let cands = candidate_handoffs(&p);
        assert_eq!(cands.len(), 2);
        assert_eq!(cands.get("a").copied(), Some(32));
        assert_eq!(cands.get("b").copied(), Some(64));
    }
}
