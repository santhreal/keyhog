//! GPU-resident e-graph substrate.
//!
//! The CPU-side `eqsat::EGraph` materialises rewrite candidates,
//! union-find merges, and cost-based extraction in a single
//! sequential walker. For wide rewrite families (algebraic
//! identities, peephole tables, pattern-match-heavy primitives)
//! the per-iteration cost grows with the e-graph size, and the
//! hash-cons table becomes the bottleneck. This module ships the
//! GPU-resident representation: a flattened, columnar mirror of
//! the EGraph that can be uploaded to a GPU buffer and walked in
//! parallel by warp-cooperative passes.
//!
//! The mirror is additive: CPU passes keep using `EGraph::saturate`,
//! while GPU-aware passes use `GpuEGraphSnapshot::from_egraph_with`
//! to materialise the columnar arrays and merge discovered equivalences
//! back through `apply_equivalences_to_egraph`.
//!
//! Soundness: the snapshot is read-only. Any equivalence the GPU
//! discovers is merged through the same `EGraph::merge` API the
//! CPU uses, so the EGraph's saturation invariants hold by
//! construction.
//!
//! ## Why the columnar layout
//!
//! Each row of the snapshot is `(eclass_id, language_op_id,
//! children_offset, children_len)`. The children indices live in
//! a separate `children: Vec<u32>` column. This layout fits a
//! GPU's coalesced-memory access pattern: a warp reading 32
//! consecutive rows touches one cache line per column (4 columns
//! × 4 bytes × 32 lanes = 512 bytes per warp).

use rustc_hash::FxHashMap;
use std::hash::BuildHasherDefault;
use std::sync::Arc;

use super::eqsat::{EClassId, EGraph, ENodeLang};

/// GPU-resident snapshot row: one entry per node in the e-graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SnapshotRow {
    /// E-class id this node belongs to (post-canonicalisation).
    pub eclass_id: u32,
    /// Stable language-op id (e.g. `BinOp::Add` → 1, `Load` → 2).
    /// The `OpIdRegistry` maintains the assignment.
    pub language_op_id: u32,
    /// Offset into the snapshot's `children` column where this
    /// node's child eclass ids start.
    pub children_offset: u32,
    /// Number of children (consecutive in the `children` column).
    pub children_len: u32,
}

/// One discovered equivalence (e-class merge candidate) produced by a
/// saturation pass. The CPU merges these back into the `EGraph`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Equivalence {
    /// Left e-class id.
    pub left: u32,
    /// Right e-class id (to be merged with left).
    pub right: u32,
}

/// Columnar GPU-uploadable mirror of an e-graph.
#[derive(Clone, Debug, Default)]
pub struct GpuEGraphSnapshot {
    /// Per-node rows in `(eclass_id, language_op_id, offset, len)` form.
    pub rows: Vec<SnapshotRow>,
    /// Flat children column. `rows[i]` references children at
    /// `children[rows[i].children_offset..rows[i].children_offset + rows[i].children_len]`.
    pub children: Vec<u32>,
    /// Op-id assignment used by `language_op_id`. Stable for the
    /// life of the snapshot.
    pub op_ids: OpIdRegistry,
}

/// Stable language-op id assignment used inside snapshot rows.
#[derive(Clone, Debug, Default)]
pub struct OpIdRegistry {
    by_name: FxHashMap<Arc<str>, u32>,
    names: Vec<Arc<str>>,
}

impl OpIdRegistry {
    /// Intern a language-op name and return its stable id.
    /// Repeated calls with the same name return the same id.
    pub fn intern(&mut self, name: &str) -> u32 {
        if let Some(&id) = self.by_name.get(name) {
            return id;
        }
        let id = u32_len(self.names.len(), "op-id registry");
        let name: Arc<str> = Arc::from(name);
        self.names.push(Arc::clone(&name));
        self.by_name.insert(name, id);
        id
    }

    /// Resolve an op-id back to its name, or `None` if unknown.
    #[must_use]
    pub fn name_of(&self, id: u32) -> Option<&str> {
        self.names.get(id as usize).map(AsRef::as_ref)
    }

    /// Number of registered op names.
    #[must_use]
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// `true` iff zero op names registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

impl GpuEGraphSnapshot {
    /// Build a snapshot from a sequence of `(eclass_id, op_name,
    /// children: &[u32])` triples. Caller-driven construction so
    /// this module doesn't depend on the exact `eqsat::EGraph`
    /// internal shape; the `EGraph` crate's adapter calls this
    /// builder to materialise the GPU mirror.
    #[must_use]
    pub fn build<'a, I>(rows: I) -> Self
    where
        I: IntoIterator<Item = (u32, &'a str, &'a [u32])>,
    {
        let mut snapshot = Self::default();
        let rows = rows.into_iter();
        let (lower_bound, _) = rows.size_hint();
        snapshot.rows.reserve(lower_bound);
        for (eclass_id, op_name, kids) in rows {
            let language_op_id = snapshot.op_ids.intern(op_name);
            let children_offset = u32_len(snapshot.children.len(), "GPU egraph children offset");
            let children_len = u32_len(kids.len(), "GPU egraph row child count");
            snapshot.children.extend_from_slice(kids);
            snapshot.rows.push(SnapshotRow {
                eclass_id,
                language_op_id,
                children_offset,
                children_len,
            });
        }
        snapshot
    }

    /// Materialise a snapshot directly from the CPU `EGraph`.
    ///
    /// The caller supplies the stable operation-name projection because
    /// `ENodeLang` is intentionally domain-generic and does not require
    /// `Debug` or a string identity. Child ids are canonicalized during the
    /// copy so the GPU columns match the CPU graph's current union-find state.
    #[must_use]
    pub fn from_egraph_with<L, F, S>(egraph: &EGraph<L>, mut op_name: F) -> Self
    where
        L: ENodeLang,
        F: FnMut(&L) -> S,
        S: AsRef<str>,
    {
        let mut snapshot = Self::default();
        snapshot.rows.reserve(egraph.class_count());
        for (eclass_id, node) in egraph.iter_nodes() {
            let language_op_id = snapshot.op_ids.intern(op_name(node).as_ref());
            let children = node.children();
            let children_offset = u32_len(snapshot.children.len(), "GPU egraph children offset");
            let children_len = u32_len(children.len(), "GPU egraph row child count");
            snapshot
                .children
                .extend(children.iter().map(|child| egraph.find_immut(*child).0));
            snapshot.rows.push(SnapshotRow {
                eclass_id: egraph.find_immut(eclass_id).0,
                language_op_id,
                children_offset,
                children_len,
            });
        }
        snapshot
    }

    /// Number of nodes in the snapshot.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.rows.len()
    }

    /// `true` iff the snapshot contains no nodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Total number of children references across all rows.
    #[must_use]
    pub fn child_count(&self) -> usize {
        self.children.len()
    }

    /// Children of the row at `row_idx`, or `None` if the snapshot row
    /// references an invalid range.
    #[must_use]
    pub fn children_of(&self, row_idx: usize) -> Option<&[u32]> {
        let row = self.rows.get(row_idx)?;
        let start = row.children_offset as usize;
        let end = start.checked_add(row.children_len as usize)?;
        self.children.get(start..end)
    }

    /// Group rows by their `eclass_id`, returning a map of
    /// `eclass_id → Vec<row_idx>`. Useful for the GPU saturation
    /// kernel's per-eclass passes.
    #[must_use]
    pub fn rows_by_eclass(&self) -> FxHashMap<u32, Vec<usize>> {
        let mut out: FxHashMap<u32, Vec<usize>> =
            FxHashMap::with_capacity_and_hasher(self.rows.len(), BuildHasherDefault::default());
        for (i, row) in self.rows.iter().enumerate() {
            out.entry(row.eclass_id).or_default().push(i);
        }
        out
    }
}

/// Report returned after applying discovered equivalences to an `EGraph`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ApplyEquivalencesReport {
    /// Input equivalence count.
    pub requested: usize,
    /// Equivalences whose e-class ids existed in the target `EGraph`.
    pub valid: usize,
    /// Direct union operations that changed the union-find root.
    pub merged: usize,
    /// Additional unions discovered during `EGraph::rebuild`.
    pub rebuild_unions: usize,
}

/// Apply a batch of GPU-discovered equivalences to a CPU-side
/// merge sink. The `merger` closure receives `(left, right)` and
/// performs the canonical `EGraph` merge. Returns the number of
/// merges that actually changed the union-find state (the merger
/// returns `true` for a state-changing merge, `false` for a no-op
/// where left and right were already in the same e-class).
pub fn apply_equivalences<F>(equivalences: &[Equivalence], mut merger: F) -> usize
where
    F: FnMut(u32, u32) -> bool,
{
    let mut applied = 0usize;
    for eq in equivalences {
        if merger(eq.left, eq.right) {
            applied += 1;
        }
    }
    applied
}

/// Apply discovered equivalences to the CPU `EGraph` and rebuild it once.
///
/// Invalid e-class ids are counted as requested but not applied; user input
/// must not be able to panic the optimizer by returning an out-of-range merge.
pub fn apply_equivalences_to_egraph<L>(
    egraph: &mut EGraph<L>,
    equivalences: &[Equivalence],
) -> ApplyEquivalencesReport
where
    L: ENodeLang,
{
    let mut report = ApplyEquivalencesReport {
        requested: equivalences.len(),
        ..ApplyEquivalencesReport::default()
    };
    let class_count = u32_len(egraph.class_count(), "CPU egraph class count");
    for eq in equivalences {
        if eq.left >= class_count || eq.right >= class_count {
            continue;
        }
        report.valid += 1;
        let left = EClassId(eq.left);
        let right = EClassId(eq.right);
        if egraph.find(left) != egraph.find(right) {
            egraph.union(left, right);
            report.merged += 1;
        }
    }
    report.rebuild_unions = egraph.rebuild();
    report
}

#[inline]
#[expect(
    clippy::expect_used,
    reason = "GPU snapshot ABI stores row offsets and ids as u32; exceeding it is a hard capacity breach"
)]
fn u32_len(value: usize, _context: &str) -> u32 {
    u32::try_from(value).expect("Fix: GPU egraph snapshot exceeds u32 encoding capacity")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::Hash;

    #[derive(Clone, Debug, Eq, Hash, PartialEq)]
    enum TinyLang {
        Lit(u32),
        Add(EClassId, EClassId),
    }

    impl ENodeLang for TinyLang {
        fn children(&self) -> super::super::eqsat::EChildren {
            match self {
                Self::Lit(_) => super::super::eqsat::EChildren::new(),
                Self::Add(left, right) => [*left, *right].into_iter().collect(),
            }
        }

        fn with_children(&self, children: &[EClassId]) -> Self {
            match self {
                Self::Lit(value) => Self::Lit(*value),
                Self::Add(_, _) => Self::Add(children[0], children[1]),
            }
        }
    }

    /// Empty snapshot: zero rows, zero children, registry empty.
    #[test]
    fn empty_snapshot() {
        let snap = GpuEGraphSnapshot::default();
        assert!(snap.is_empty());
        assert_eq!(snap.node_count(), 0);
        assert_eq!(snap.child_count(), 0);
        assert!(snap.op_ids.is_empty());
    }

    /// Build a 3-node snapshot via the iterator builder; assert
    /// row layout + children column line up.
    #[test]
    fn build_three_node_snapshot() {
        let snap = GpuEGraphSnapshot::build([
            (0u32, "lit_u32", &[][..]),
            (1u32, "lit_u32", &[][..]),
            (2u32, "binop_add", &[0u32, 1u32][..]),
        ]);
        assert_eq!(snap.node_count(), 3);
        assert_eq!(snap.child_count(), 2);
        let empty: &[u32] = &[];
        assert_eq!(snap.children_of(0), Some(empty));
        assert_eq!(snap.children_of(1), Some(empty));
        assert_eq!(snap.children_of(2), Some(&[0, 1][..]));
        assert_eq!(snap.children_of(99), None);
    }

    /// `OpIdRegistry::intern` returns the same id for repeated
    /// names.
    #[test]
    fn op_id_intern_dedups() {
        let mut reg = OpIdRegistry::default();
        let a = reg.intern("foo");
        let b = reg.intern("bar");
        let c = reg.intern("foo");
        assert_eq!(a, c);
        assert_ne!(a, b);
        assert_eq!(reg.len(), 2);
        assert_eq!(reg.name_of(a), Some("foo"));
        assert_eq!(reg.name_of(b), Some("bar"));
        assert_eq!(reg.name_of(99), None);
    }

    /// `rows_by_eclass` groups multi-row e-classes.
    #[test]
    fn rows_by_eclass_groups_correctly() {
        let snap = GpuEGraphSnapshot::build([
            (0u32, "lit_u32", &[][..]),
            (0u32, "var", &[][..]),
            (1u32, "binop_add", &[0u32][..]),
        ]);
        let groups = snap.rows_by_eclass();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups.get(&0).unwrap().len(), 2);
        assert_eq!(groups.get(&1).unwrap().len(), 1);
    }

    /// Snapshot directly from the CPU EGraph canonicalizes children and
    /// assigns stable operation ids.
    #[test]
    fn snapshot_from_egraph_uses_canonical_children() {
        let mut egraph = EGraph::new();
        let a = egraph.add(TinyLang::Lit(1));
        let b = egraph.add(TinyLang::Lit(2));
        let add = egraph.add(TinyLang::Add(a, b));
        assert_eq!(add.0, 2);

        let snap = GpuEGraphSnapshot::from_egraph_with(&egraph, |node| match node {
            TinyLang::Lit(_) => "lit",
            TinyLang::Add(_, _) => "add",
        });

        assert_eq!(snap.node_count(), 3);
        assert_eq!(snap.child_count(), 2);
        assert_eq!(snap.op_ids.name_of(0), Some("lit"));
        assert_eq!(snap.op_ids.name_of(1), Some("add"));
        assert_eq!(snap.children_of(2), Some(&[0, 1][..]));
    }

    /// `apply_equivalences` calls the merger for each equivalence
    /// and counts state-changing merges.
    #[test]
    fn apply_equivalences_counts_state_changes() {
        let equivalences = vec![
            Equivalence { left: 0, right: 1 },
            Equivalence { left: 1, right: 0 }, // no-op (already merged)
            Equivalence { left: 2, right: 3 },
        ];
        let mut canonical: FxHashMap<u32, u32> = FxHashMap::default();
        let applied = apply_equivalences(&equivalences, |a, b| {
            let canon_a = *canonical.get(&a).unwrap_or(&a);
            let canon_b = *canonical.get(&b).unwrap_or(&b);
            if canon_a == canon_b {
                false
            } else {
                let (lo, hi) = if canon_a < canon_b {
                    (canon_a, canon_b)
                } else {
                    (canon_b, canon_a)
                };
                canonical.insert(hi, lo);
                canonical.insert(a, lo);
                canonical.insert(b, lo);
                true
            }
        });
        assert_eq!(applied, 2);
    }

    /// Empty equivalence batch is a no-op.
    #[test]
    fn apply_equivalences_empty_batch() {
        let applied = apply_equivalences(&[], |_, _| true);
        assert_eq!(applied, 0);
    }

    /// EGraph merge bridge ignores invalid ids and rebuilds after valid
    /// merges.
    #[test]
    fn apply_equivalences_to_egraph_merges_valid_ids() {
        let mut egraph = EGraph::new();
        let a = egraph.add(TinyLang::Lit(1));
        let b = egraph.add(TinyLang::Lit(2));
        let c = egraph.add(TinyLang::Lit(3));
        let report = apply_equivalences_to_egraph(
            &mut egraph,
            &[
                Equivalence {
                    left: a.0,
                    right: b.0,
                },
                Equivalence {
                    left: c.0,
                    right: 99,
                },
            ],
        );
        assert_eq!(
            report,
            ApplyEquivalencesReport {
                requested: 2,
                valid: 1,
                merged: 1,
                rebuild_unions: 0,
            }
        );
        assert_eq!(egraph.find(a), egraph.find(b));
        assert_ne!(egraph.find(a), egraph.find(c));
    }
}
