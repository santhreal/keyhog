//! Equality-saturation engine — minimal `EGraph` substrate for vyre IR
//! algebraic rewrite families.
//!
//! Op id: `vyre-foundation::optimizer::eqsat`. Soundness: every equivalence
//! added to the `EGraph` must be a true semantic equality of the underlying
//! IR. Cost-direction: extraction phase picks the lowest-cost equivalent
//! representative under a caller-supplied cost function — guaranteed
//! cost-monotone-down by construction.
//!
//! ## Why
//!
//! Pass-by-pass rewriting commits to a single rewrite at every step. When
//! two passes both want to fire on the same expression, one wins
//! (whichever is scheduled first), even if the other would have unlocked
//! a much better optimization downstream. Equality saturation sidesteps
//! this by accumulating all known equivalences into one `EGraph`, running
//! every rewrite rule to a fixed point, and then extracting the
//! lowest-cost equivalent at the end.
//!
//! This module ships the substrate: a minimal but sound `EGraph` with
//! hashcons, union-find, rebuild, saturation, and a `Family` trait
//! that wraps a set of related rewrite rules.
//!
//! ## `ENode`
//!
//! `ENodes` are domain-specific: each family defines its own `ENode` enum.
//! The substrate is generic over `Lang: ENodeLang` which provides the
//! children-iteration API the `EGraph` needs to canonicalize and rebuild.
//!
//! ## Why not import egg
//!
//! This implementation is intentionally minimal so it lives entirely
//! within `vyre-foundation` with no external dep, no proc-macro, and
//! no per-rule code generation. The egg crate is more featureful but
//! adds a dependency tree that conflicts with vyre's "every dep is a
//! supply-chain risk" stance.

use std::hash::{BuildHasherDefault, Hash, Hasher};

use rustc_hash::FxHashMap;
use rustc_hash::FxHasher;
use smallvec::SmallVec;

/// Stack-backed child list used by `EGraph` node APIs. Most IR algebra nodes
/// have 0-3 children; keeping that path inline avoids allocator traffic during
/// saturation.
pub type EChildren = SmallVec<[EClassId; 4]>;

/// Identifier of an `EClass` in the `EGraph`. `EClasses` are dense u32-indexed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EClassId(pub u32);

/// Domain-specific `ENode` language. Implementations describe how to
/// iterate the children of a node (for canonicalization) and how to
/// rebuild a node with replacement child ids (for rebuild).
pub trait ENodeLang: Clone + Eq + Hash {
    /// Iterate the `EClass`-child ids referenced by this node, in order.
    fn children(&self) -> EChildren;

    /// Rebuild this node with replacement `EClass` children. The returned
    /// node has the same shape as `self` but with each child replaced by
    /// the corresponding entry in `children`. `children.len()` must equal
    /// `self.children().len()`.
    #[must_use]
    fn with_children(&self, children: &[EClassId]) -> Self;
}

/// One equivalence class — the set of all `ENodes` proven equal so far.
#[derive(Debug, Clone)]
pub struct EClass<L: ENodeLang> {
    /// Every `ENode` that lives in this class (canonicalized form).
    pub nodes: Vec<L>,
    /// `EClasses` that have THIS one as a child — used during rebuild to
    /// propagate canonicalization.
    pub parents: Vec<EClassId>,
}

/// The `EGraph`: a union-find of `EClasses` + a hashcons mapping
/// canonicalized `ENodes` to their `EClass`.
#[derive(Debug, Clone)]
pub struct EGraph<L: ENodeLang> {
    /// Class storage (dense). The class at index `i` is `EClass(i)`.
    classes: Vec<EClass<L>>,
    /// Hashcons: canonicalized `ENode` → `EClassId`. Maintained incrementally
    /// by `add()` and rebuilt after `union()` operations.
    hashcons: FxHashMap<L, EClassId>,
    /// Union-find parent pointers for path-compression find.
    parent: Vec<EClassId>,
    /// Set of `EClasses` that need rebuild after a union — drained by
    /// `rebuild()`.
    pending: Vec<EClassId>,
}

impl<L: ENodeLang> Default for EGraph<L> {
    fn default() -> Self {
        Self::new()
    }
}

impl<L: ENodeLang> EGraph<L> {
    /// Create an empty `EGraph`.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(0)
    }

    /// Create an `EGraph` with capacity for an expected number of `EClasses`.
    #[must_use]
    pub fn with_capacity(class_capacity: usize) -> Self {
        Self {
            classes: Vec::with_capacity(class_capacity),
            hashcons: FxHashMap::with_capacity_and_hasher(
                class_capacity,
                BuildHasherDefault::default(),
            ),
            parent: Vec::with_capacity(class_capacity),
            pending: Vec::with_capacity(class_capacity),
        }
    }

    /// Number of `EClasses` currently in the graph.
    #[must_use]
    pub fn class_count(&self) -> usize {
        self.classes.len()
    }

    /// Find the canonical class representative via path compression.
    pub fn find(&mut self, id: EClassId) -> EClassId {
        let mut cur = id;
        while self.parent[cur.0 as usize] != cur {
            cur = self.parent[cur.0 as usize];
        }
        // Path compression.
        let mut walk = id;
        while self.parent[walk.0 as usize] != cur {
            let next = self.parent[walk.0 as usize];
            self.parent[walk.0 as usize] = cur;
            walk = next;
        }
        cur
    }

    /// Find a canonical class without path compression — for read-only
    /// use during iteration.
    #[must_use]
    pub fn find_immut(&self, id: EClassId) -> EClassId {
        let mut cur = id;
        while self.parent[cur.0 as usize] != cur {
            cur = self.parent[cur.0 as usize];
        }
        cur
    }

    /// Canonicalize a node by replacing each child with its current
    /// canonical `EClass`.
    fn canonicalize(&self, node: &L) -> L {
        let canon_children: EChildren = node
            .children()
            .into_iter()
            .map(|c| self.find_immut(c))
            .collect();
        node.with_children(&canon_children)
    }

    /// Add a node to the `EGraph`. If an equivalent node already exists,
    /// return its `EClassId`; otherwise create a new `EClass`.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "public insertion API consumes language nodes; canonicalized misses store an owned node"
    )]
    pub fn add(&mut self, node: L) -> EClassId {
        let canon = self.canonicalize(&node);
        if let Some(&existing) = self.hashcons.get(&canon) {
            return self.find(existing);
        }
        let new_id = eclass_id_from_index(self.classes.len());
        self.parent.push(new_id);
        // Register `new_id` as a parent of each child class.
        for child in canon.children() {
            let child_canon = self.find(child);
            if let Some(class) = self.classes.get_mut(child_canon.0 as usize) {
                class.parents.push(new_id);
            }
        }
        let nodes = vec![canon.clone()];
        self.classes.push(EClass {
            nodes,
            parents: Vec::new(),
        });
        self.hashcons.insert(canon, new_id);
        new_id
    }

    /// Equate two `EClasses`. The returned id is the canonical class for
    /// both inputs after the union. Calls to `add()` on equivalent nodes
    /// will return this same id.
    ///
    /// Caller must invoke `rebuild()` after a batch of `union()` calls
    /// to re-canonicalize the hashcons + propagate equivalences upward
    /// through parent pointers.
    pub fn union(&mut self, a: EClassId, b: EClassId) -> EClassId {
        let a_root = self.find(a);
        let b_root = self.find(b);
        if a_root == b_root {
            return a_root;
        }
        // Union with the smaller-id-as-root convention for determinism.
        let (winner, loser) = if a_root.0 < b_root.0 {
            (a_root, b_root)
        } else {
            (b_root, a_root)
        };
        self.parent[loser.0 as usize] = winner;
        // Merge nodes + parent lists into the winning class.
        let loser_class = std::mem::replace(
            &mut self.classes[loser.0 as usize],
            EClass {
                nodes: Vec::new(),
                parents: Vec::new(),
            },
        );
        self.classes[winner.0 as usize]
            .nodes
            .extend(loser_class.nodes);
        self.classes[winner.0 as usize]
            .parents
            .extend(loser_class.parents);
        // Schedule the winner for rebuild — its parents may now be
        // canonicalizable.
        self.pending.push(winner);
        winner
    }

    /// Re-canonicalize the hashcons after a batch of `union()` calls.
    /// Returns the number of additional unions discovered transitively.
    pub fn rebuild(&mut self) -> usize {
        let mut new_unions = 0;
        while let Some(class_id) = self.pending.pop() {
            let canonical = self.find(class_id);
            // Re-canonicalize every node in the canonical class.
            let nodes = std::mem::take(&mut self.classes[canonical.0 as usize].nodes);
            let mut canon_nodes = Vec::with_capacity(nodes.len());
            for node in nodes {
                let new_canon = self.canonicalize(&node);
                // Re-insert into hashcons; collisions trigger more unions.
                if let Some(&existing) = self.hashcons.get(&new_canon) {
                    let existing_canon = self.find(existing);
                    if existing_canon != canonical {
                        let unified = self.union(existing_canon, canonical);
                        new_unions += 1;
                        if unified != canonical {
                            // The winner changed — re-find at top of loop.
                            self.pending.push(unified);
                        }
                    }
                }
                self.hashcons.insert(new_canon.clone(), canonical);
                canon_nodes.push(new_canon);
            }
            dedup_enodes_by_hash(&mut canon_nodes);
            self.classes[canonical.0 as usize].nodes = canon_nodes;
        }
        new_unions
    }

    /// Iterate every (`EClassId`, `ENode`) pair currently in the graph.
    /// Useful for rule application and extraction.
    pub fn iter_nodes(&self) -> impl Iterator<Item = (EClassId, &L)> {
        self.classes
            .iter()
            .enumerate()
            .filter_map(|(idx, class)| {
                let class_id = eclass_id_from_index(idx);
                (self.parent[idx] == class_id).then_some((class_id, class))
            })
            .flat_map(|(class_id, class)| class.nodes.iter().map(move |n| (class_id, n)))
    }

    /// Read-only access to a class by id.
    #[must_use]
    pub fn class(&self, id: EClassId) -> Option<&EClass<L>> {
        let canon = self.find_immut(id);
        self.classes.get(canon.0 as usize)
    }
}

#[expect(
    clippy::expect_used,
    reason = "EClassId is the compact u32 egraph handle; exceeding it is a hard capacity breach"
)]
fn eclass_id_from_index(index: usize) -> EClassId {
    EClassId(u32::try_from(index).expect("Fix: egraph class index exceeds u32 EClassId capacity"))
}

fn dedup_enodes_by_hash<L: ENodeLang>(nodes: &mut Vec<L>) {
    if nodes.len() <= 1 {
        return;
    }
    let mut keyed = Vec::with_capacity(nodes.len());
    keyed.extend(nodes.drain(..).map(|node| (stable_enode_hash(&node), node)));
    keyed.sort_unstable_by_key(|(hash, _)| *hash);
    let mut deduped: Vec<(u64, L)> = Vec::with_capacity(keyed.len());
    for (hash, node) in keyed {
        let duplicate_in_hash_bucket = deduped
            .iter()
            .rev()
            .take_while(|(existing_hash, _)| *existing_hash == hash)
            .any(|(_, existing)| existing == &node);
        if !duplicate_in_hash_bucket {
            deduped.push((hash, node));
        }
    }
    nodes.extend(deduped.into_iter().map(|(_, node)| node));
}

fn stable_enode_hash<L: ENodeLang>(node: &L) -> u64 {
    let mut hasher = FxHasher::default();
    node.hash(&mut hasher);
    hasher.finish()
}

/// One equality-saturation rewrite rule. Returns a list of `(left, right)`
/// `EClass` pairs that should be unioned after the rule fires.
///
/// Implementations walk the `EGraph` (via `iter_nodes`), pattern-match on
/// shapes they recognize, and return the equivalences they want to add.
pub trait Rule<L: ENodeLang> {
    /// Human-readable rule name for telemetry + tests.
    fn name(&self) -> &'static str;

    /// Find every match of this rule's LHS pattern in `egraph` and return
    /// the (a, b) pairs that should be equated.
    fn matches(&self, egraph: &EGraph<L>) -> Vec<(EClassId, EClassId)>;
}

/// A family of related rewrite rules.
pub trait Family<L: ENodeLang> {
    /// Family name (e.g. "`commutative_arith`").
    fn name(&self) -> &'static str;

    /// Vec of rules in this family. Stored as boxed trait objects so a
    /// single family can mix rule shapes (literal-matching, pattern-
    /// matching, conditional rewrites).
    fn rules(&self) -> Vec<Box<dyn Rule<L>>>;
}

/// Run rules to fixed point or `max_iters`, whichever comes first.
/// Returns the iteration count actually used.
pub fn saturate<L: ENodeLang>(
    egraph: &mut EGraph<L>,
    rules: &[Box<dyn Rule<L>>],
    max_iters: usize,
) -> usize {
    let mut equivalences = Vec::with_capacity(egraph.class_count());
    for iter in 0..max_iters {
        equivalences.clear();
        for rule in rules {
            equivalences.extend(rule.matches(egraph));
        }
        if equivalences.is_empty() {
            return iter;
        }
        for (a, b) in equivalences.drain(..) {
            egraph.union(a, b);
        }
        let extra = egraph.rebuild();
        if extra == 0 && egraph.pending.is_empty() {
            // Nothing else to propagate; still need to check if rules find
            // anything new on the next iter.
        }
    }
    max_iters
}

/// Adapter that gates a base [`Rule`] on a device-fact predicate.
///
/// ROADMAP A9. The "should this rule fire on this hardware?" check
/// recurs across every device-aware Rule (FP16 only on `supports_f16`,
/// tensor-core fusion only on `supports_tensor_cores`, subgroup
/// shuffle only on `has_subgroup_shuffle`). Without a shared adapter,
/// every Rule re-implements the same `if !facts.feature { return
/// vec![] }` preamble. This wrapper centralises it.
///
/// `DeviceFacts` is a free-form caller-owned object so the foundation
/// crate does not pull `DeviceProfile` (which lives in `vyre-driver`)
/// into its dependency graph. Callers either pass a borrowed
/// `&DeviceProfile` directly via the `predicate` closure capture, or
/// thread a snapshot through their own type.
///
/// When `predicate` returns `false` the wrapped rule's [`matches`]
/// short-circuits to an empty vector — the saturation loop sees no
/// equivalences and the rule contributes nothing. When `true`, the
/// wrapped rule fires unchanged.
pub struct DeviceAwareRule<L: ENodeLang, F: Fn() -> bool> {
    inner: Box<dyn Rule<L>>,
    predicate: F,
}

impl<L: ENodeLang, F: Fn() -> bool> DeviceAwareRule<L, F> {
    /// Wrap `inner` so it only fires when `predicate()` returns true.
    pub fn new(inner: Box<dyn Rule<L>>, predicate: F) -> Self {
        Self { inner, predicate }
    }
}

impl<L: ENodeLang, F: Fn() -> bool> Rule<L> for DeviceAwareRule<L, F> {
    fn name(&self) -> &'static str {
        self.inner.name()
    }
    fn matches(&self, egraph: &EGraph<L>) -> Vec<(EClassId, EClassId)> {
        if (self.predicate)() {
            self.inner.matches(egraph)
        } else {
            Vec::new()
        }
    }
}

/// One family's saturation result: how many iterations were spent in
/// that family's [`saturate`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilySaturationReport {
    /// Family name as returned by [`Family::name`].
    pub family: &'static str,
    /// Iterations the family actually used (≤ `budget`). 0 when the
    /// budget was 0 or when the rule set converged immediately.
    pub iters_used: usize,
    /// Budget the family was given. Echoed back so callers can compare
    /// against `iters_used` without re-querying the budget function.
    pub budget: usize,
}

/// Run each family with its own iteration budget.
///
/// Saturate-per-family is the prerequisite for ROADMAP A8: a global
/// `max_iters` punishes algebraic families (which converge in 2-3 iters)
/// for sharing a budget with slow rewrite families (which may need 50+).
/// The fix is to give each family its own cap — algebraic gets the small
/// cap it needs, structural rewrite gets the larger one, and neither
/// starves the other.
///
/// Order: families run in the order they appear in `families`. Earlier
/// families' merges are visible to later families (the `EGraph` carries
/// state across calls). Re-running this wrapper after a third-party
/// pass mutates the `EGraph` is safe — each call is independent.
///
/// `budget_for` is queried once per family to allow callers to pull
/// per-family caps from a TOML config or cost model. Returning 0 skips
/// the family without running it.
pub fn saturate_per_family<L: ENodeLang>(
    egraph: &mut EGraph<L>,
    families: &[&dyn Family<L>],
    budget_for: impl Fn(&str) -> usize,
) -> Vec<FamilySaturationReport> {
    let mut out = Vec::with_capacity(families.len());
    for family in families {
        let name = family.name();
        let budget = budget_for(name);
        if budget == 0 {
            out.push(FamilySaturationReport {
                family: name,
                iters_used: 0,
                budget: 0,
            });
            continue;
        }
        let rules = family.rules();
        let iters_used = saturate(egraph, &rules, budget);
        out.push(FamilySaturationReport {
            family: name,
            iters_used,
            budget,
        });
    }
    out
}

/// Extract the lowest-cost equivalent representation of `class_id` under
/// `cost_fn`. Returns the chosen `ENode` and its computed cost.
///
/// Greedy bottom-up extraction: cost of each `EClass` is the min over its
/// nodes of `cost_fn(node) + sum(cost_of_child_classes)`. Iterates to
/// fixed point on the cost map.
pub fn extract_best<L: ENodeLang>(
    egraph: &EGraph<L>,
    class_id: EClassId,
    cost_fn: impl Fn(&L) -> u64,
) -> Option<(L, u64)> {
    // VYRE_IR_HOTSPOTS HIGH: extract_best is the inner loop of every
    // optimizer extraction (called per device per root by
    // device_extraction). The previous FxHashMap<EClassId, (L,u64)>
    // hashed-lookup'd costs three times per node per iteration
    // (canon_cid, every child, and the insert check). Class ids are
    // dense u32s in [0, class_count); a direct Vec<Option<(L,u64)>>
    // cuts every lookup to a u32 deref. Plus iter_nodes already
    // filters for canonical (parent[idx] == idx), so the find_immut
    // on `cid` was redundant work — drop it.
    let class_count = egraph.class_count();
    let mut costs: Vec<Option<(L, u64)>> = (0..class_count).map(|_| None).collect();
    let mut changed = true;
    let mut iters = 0;
    while changed && iters < 1024 {
        changed = false;
        iters += 1;
        for (cid, node) in egraph.iter_nodes() {
            // cid is already canonical — iter_nodes filters parent[idx] == idx.
            let canon_cid_idx = cid.0 as usize;
            let mut node_cost = cost_fn(node);
            let mut child_overflow = false;
            for child in node.children() {
                let canon_child = egraph.find_immut(child);
                let canon_child_idx = canon_child.0 as usize;
                if let Some((_, c)) = costs.get(canon_child_idx).and_then(Option::as_ref) {
                    node_cost = node_cost.saturating_add(*c);
                } else {
                    child_overflow = true;
                    break;
                }
            }
            if child_overflow {
                continue;
            }
            let Some(slot) = costs.get_mut(canon_cid_idx) else {
                continue;
            };
            match slot {
                Some((_, existing_cost)) if *existing_cost <= node_cost => {}
                _ => {
                    *slot = Some((node.clone(), node_cost));
                    changed = true;
                }
            }
        }
    }
    let canon = egraph.find_immut(class_id);
    costs.get(canon.0 as usize).and_then(Clone::clone)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustc_hash::FxHashSet;
    use smallvec::smallvec;

    /// A minimal arithmetic `ENode` language for engine tests.
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    enum Arith {
        Const(u32),
        Add(EClassId, EClassId),
        Mul(EClassId, EClassId),
    }

    impl ENodeLang for Arith {
        fn children(&self) -> EChildren {
            match self {
                Self::Const(_) => EChildren::new(),
                Self::Add(a, b) | Self::Mul(a, b) => smallvec![*a, *b],
            }
        }

        fn with_children(&self, children: &[EClassId]) -> Self {
            match self {
                Self::Const(n) => Self::Const(*n),
                Self::Add(_, _) => Self::Add(children[0], children[1]),
                Self::Mul(_, _) => Self::Mul(children[0], children[1]),
            }
        }
    }

    /// Simple cost: 1 per Const, 2 per Add, 3 per Mul.
    fn arith_cost(node: &Arith) -> u64 {
        match node {
            Arith::Const(_) => 1,
            Arith::Add(_, _) => 2,
            Arith::Mul(_, _) => 3,
        }
    }

    #[test]
    fn empty_egraph_has_zero_classes() {
        let egraph: EGraph<Arith> = EGraph::new();
        assert_eq!(egraph.class_count(), 0);
    }

    #[test]
    fn add_const_creates_one_class() {
        let mut egraph: EGraph<Arith> = EGraph::new();
        let _ = egraph.add(Arith::Const(7));
        assert_eq!(egraph.class_count(), 1);
    }

    #[test]
    fn add_same_const_twice_returns_same_class() {
        let mut egraph: EGraph<Arith> = EGraph::new();
        let a = egraph.add(Arith::Const(7));
        let b = egraph.add(Arith::Const(7));
        assert_eq!(a, b);
        assert_eq!(egraph.class_count(), 1);
    }

    #[test]
    fn add_distinct_consts_creates_distinct_classes() {
        let mut egraph: EGraph<Arith> = EGraph::new();
        let a = egraph.add(Arith::Const(7));
        let b = egraph.add(Arith::Const(8));
        assert_ne!(a, b);
        assert_eq!(egraph.class_count(), 2);
    }

    #[test]
    fn add_compound_node_creates_proper_class() {
        let mut egraph: EGraph<Arith> = EGraph::new();
        let a = egraph.add(Arith::Const(1));
        let b = egraph.add(Arith::Const(2));
        let sum = egraph.add(Arith::Add(a, b));
        assert_eq!(egraph.class_count(), 3);
        assert_ne!(sum, a);
        assert_ne!(sum, b);
    }

    #[test]
    fn union_merges_two_classes() {
        let mut egraph: EGraph<Arith> = EGraph::new();
        let a = egraph.add(Arith::Const(1));
        let b = egraph.add(Arith::Const(2));
        let unified = egraph.union(a, b);
        assert_eq!(egraph.find(a), unified);
        assert_eq!(egraph.find(b), unified);
    }

    #[test]
    fn union_is_idempotent() {
        let mut egraph: EGraph<Arith> = EGraph::new();
        let a = egraph.add(Arith::Const(1));
        let b = egraph.add(Arith::Const(2));
        let first = egraph.union(a, b);
        let second = egraph.union(a, b);
        assert_eq!(first, second);
    }

    #[test]
    fn rebuild_canonicalizes_compound_nodes_after_union() {
        // Build (1 + 2). Union 1 and 2. After rebuild, two adds that look
        // structurally different should canonicalize to the same form.
        let mut egraph: EGraph<Arith> = EGraph::new();
        let one = egraph.add(Arith::Const(1));
        let two = egraph.add(Arith::Const(2));
        let _add_12 = egraph.add(Arith::Add(one, two));
        let _add_22 = egraph.add(Arith::Add(two, two));
        egraph.union(one, two);
        let _ = egraph.rebuild();
        // After rebuild, Add(1,2) and Add(2,2) canonicalize to the same
        // pair of children → same EClass.
        let post_one = egraph.find(one);
        let post_two = egraph.find(two);
        assert_eq!(post_one, post_two, "1 and 2 must be in the same class");
    }

    #[test]
    fn extract_best_picks_cheapest_equivalent() {
        // Build two equivalent representations: Add(1, 2) and Const(3).
        // Equate them. Extract should pick Const(3) (cost 1) over Add (cost 4).
        let mut egraph: EGraph<Arith> = EGraph::new();
        let one = egraph.add(Arith::Const(1));
        let two = egraph.add(Arith::Const(2));
        let three = egraph.add(Arith::Const(3));
        let add_12 = egraph.add(Arith::Add(one, two));
        egraph.union(add_12, three);
        let _ = egraph.rebuild();
        let (best, cost) = extract_best(&egraph, add_12, arith_cost).expect("must extract");
        assert_eq!(best, Arith::Const(3));
        assert_eq!(cost, 1);
    }

    #[test]
    fn extract_best_returns_only_node_when_no_alternatives() {
        let mut egraph: EGraph<Arith> = EGraph::new();
        let a = egraph.add(Arith::Const(42));
        let (best, cost) = extract_best(&egraph, a, arith_cost).expect("must extract");
        assert_eq!(best, Arith::Const(42));
        assert_eq!(cost, 1);
    }

    /// Simpler test rule: union every two `Const(a)` with `Const(a)` (idempotent).
    /// Used to verify `saturate` calls `matches` and `rebuild` correctly.
    struct UnionEqualConstsRule;

    impl Rule<Arith> for UnionEqualConstsRule {
        fn name(&self) -> &'static str {
            "union_equal_consts"
        }

        fn matches(&self, egraph: &EGraph<Arith>) -> Vec<(EClassId, EClassId)> {
            let mut by_value: FxHashMap<u32, Vec<EClassId>> = FxHashMap::default();
            for (cid, node) in egraph.iter_nodes() {
                if let Arith::Const(v) = node {
                    by_value.entry(*v).or_default().push(cid);
                }
            }
            let mut out = Vec::new();
            for ids in by_value.values() {
                for window in ids.windows(2) {
                    out.push((window[0], window[1]));
                }
            }
            out
        }
    }

    #[test]
    fn saturate_runs_to_fixed_point() {
        let mut egraph: EGraph<Arith> = EGraph::new();
        // Hashcons should already prevent two Const(7)s, but this exercises
        // the saturate loop end-to-end with a real rule.
        let _a = egraph.add(Arith::Const(7));
        let _b = egraph.add(Arith::Const(8));
        let rules: Vec<Box<dyn Rule<Arith>>> = vec![Box::new(UnionEqualConstsRule)];
        let iters = saturate(&mut egraph, &rules, 10);
        assert!(iters <= 10);
        // No new equivalences past the first iter (hashcons already
        // dedupes), so saturate returns 0 or 1.
        assert!(iters <= 1);
    }

    #[test]
    fn find_immut_returns_canonical_after_union() {
        let mut egraph: EGraph<Arith> = EGraph::new();
        let a = egraph.add(Arith::Const(1));
        let b = egraph.add(Arith::Const(2));
        egraph.union(a, b);
        // find_immut must agree with find.
        let canon_a = egraph.find_immut(a);
        let canon_b = egraph.find_immut(b);
        assert_eq!(canon_a, canon_b);
    }

    #[test]
    fn class_lookup_returns_canonical_class() {
        let mut egraph: EGraph<Arith> = EGraph::new();
        let a = egraph.add(Arith::Const(7));
        let class = egraph.class(a).expect("class must exist");
        assert!(matches!(class.nodes[0], Arith::Const(7)));
    }

    #[test]
    fn rebuild_propagates_through_parents() {
        // Build Add(1, 2). Union 1 and 2. After rebuild, Add(1,2) should
        // canonicalize to Add(1,1) (or whichever survived).
        let mut egraph: EGraph<Arith> = EGraph::new();
        let one = egraph.add(Arith::Const(1));
        let two = egraph.add(Arith::Const(2));
        let add_12 = egraph.add(Arith::Add(one, two));
        egraph.union(one, two);
        let _ = egraph.rebuild();
        // The Add(1,2) class should still be findable, and its node should
        // now reference the unified child class.
        let class = egraph.class(add_12).expect("class must still exist");
        match &class.nodes[0] {
            Arith::Add(a, b) => {
                let canon_a = egraph.find_immut(*a);
                let canon_b = egraph.find_immut(*b);
                assert_eq!(
                    canon_a, canon_b,
                    "Add(1,2)'s children must canonicalize to the same class after union"
                );
            }
            other => panic!("expected Add; got {other:?}"),
        }
    }

    /// Rule that pairs every Const id with itself — guaranteed to
    /// produce at least one match whenever the egraph holds any Const.
    /// Used purely as a forwarding-test fixture.
    struct PairConstSelfRule;

    impl Rule<Arith> for PairConstSelfRule {
        fn name(&self) -> &'static str {
            "pair_const_self"
        }

        fn matches(&self, egraph: &EGraph<Arith>) -> Vec<(EClassId, EClassId)> {
            let mut out = Vec::new();
            for (cid, node) in egraph.iter_nodes() {
                if let Arith::Const(_) = node {
                    out.push((cid, cid));
                }
            }
            out
        }
    }

    #[test]
    fn device_aware_rule_predicate_true_forwards_matches() {
        // First half: with no Consts, even the always-on inner rule
        // produces no matches. The forwarder must propagate that.
        let egraph: EGraph<Arith> = EGraph::new();
        let inner: Box<dyn Rule<Arith>> = Box::new(PairConstSelfRule);
        let rule = DeviceAwareRule::new(inner, || true);
        assert!(
            rule.matches(&egraph).is_empty(),
            "empty egraph must yield empty matches even with predicate true"
        );

        // Second half: add a Const and confirm the predicate-true
        // forwarder surfaces the inner rule's hits.
        let mut egraph: EGraph<Arith> = EGraph::new();
        let _a = egraph.add(Arith::Const(7));
        let inner: Box<dyn Rule<Arith>> = Box::new(PairConstSelfRule);
        let rule = DeviceAwareRule::new(inner, || true);
        assert!(
            !rule.matches(&egraph).is_empty(),
            "predicate true must forward the inner rule's matches"
        );
    }

    #[test]
    fn device_aware_rule_predicate_false_returns_empty() {
        let mut egraph: EGraph<Arith> = EGraph::new();
        let _ = egraph.add(Arith::Const(7));
        let _ = egraph.add(Arith::Const(7)); // hashcons collapses, but rule loop still scans
        let inner: Box<dyn Rule<Arith>> = Box::new(UnionEqualConstsRule);
        let rule = DeviceAwareRule::new(inner, || false);
        let matches = rule.matches(&egraph);
        assert!(
            matches.is_empty(),
            "predicate false must short-circuit to empty"
        );
    }

    #[test]
    fn device_aware_rule_forwards_inner_name() {
        let inner: Box<dyn Rule<Arith>> = Box::new(UnionEqualConstsRule);
        let rule = DeviceAwareRule::new(inner, || true);
        assert_eq!(rule.name(), "union_equal_consts");
    }

    /// A toy family with one rule, used for the per-family budget tests.
    struct ConstUnionFamily {
        name: &'static str,
    }

    impl Family<Arith> for ConstUnionFamily {
        fn name(&self) -> &'static str {
            self.name
        }
        fn rules(&self) -> Vec<Box<dyn Rule<Arith>>> {
            vec![Box::new(UnionEqualConstsRule)]
        }
    }

    #[test]
    fn saturate_per_family_skips_zero_budget() {
        let mut egraph: EGraph<Arith> = EGraph::new();
        let _ = egraph.add(Arith::Const(7));
        let fam = ConstUnionFamily { name: "f0" };
        let report = saturate_per_family(&mut egraph, &[&fam], |_| 0);
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].family, "f0");
        assert_eq!(report[0].iters_used, 0);
        assert_eq!(report[0].budget, 0);
    }

    #[test]
    fn saturate_per_family_runs_each_family_independently() {
        let mut egraph: EGraph<Arith> = EGraph::new();
        let _ = egraph.add(Arith::Const(1));
        let _ = egraph.add(Arith::Const(2));
        let fam_a = ConstUnionFamily { name: "alpha" };
        let fam_b = ConstUnionFamily { name: "beta" };
        let report = saturate_per_family(&mut egraph, &[&fam_a, &fam_b], |name| match name {
            "alpha" => 3,
            "beta" => 5,
            _ => 0,
        });
        assert_eq!(report.len(), 2);
        assert_eq!(report[0].family, "alpha");
        assert_eq!(report[0].budget, 3);
        assert!(report[0].iters_used <= 3);
        assert_eq!(report[1].family, "beta");
        assert_eq!(report[1].budget, 5);
        assert!(report[1].iters_used <= 5);
    }

    #[test]
    fn saturate_per_family_empty_input_returns_empty() {
        let mut egraph: EGraph<Arith> = EGraph::new();
        let report = saturate_per_family(&mut egraph, &[], |_| 10);
        assert!(report.is_empty());
    }

    #[test]
    fn saturate_per_family_reports_iters_used_le_budget() {
        let mut egraph: EGraph<Arith> = EGraph::new();
        let _ = egraph.add(Arith::Const(1));
        let _ = egraph.add(Arith::Const(2));
        let fam = ConstUnionFamily { name: "single" };
        let report = saturate_per_family(&mut egraph, &[&fam], |_| 100);
        assert_eq!(report.len(), 1);
        assert!(
            report[0].iters_used <= report[0].budget,
            "iters_used ({}) must not exceed budget ({})",
            report[0].iters_used,
            report[0].budget
        );
    }

    #[test]
    fn iter_nodes_visits_only_canonical_classes() {
        let mut egraph: EGraph<Arith> = EGraph::new();
        let a = egraph.add(Arith::Const(1));
        let b = egraph.add(Arith::Const(2));
        egraph.union(a, b);
        let _ = egraph.rebuild();
        // iter_nodes yields one entry per (class, node) pair. After union,
        // the loser class is filtered out (its parent points elsewhere),
        // but the merged winner class holds both Const(1) and Const(2)
        // nodes. So the canonical-class set has size 1, but the (class,
        // node) entry count is 2.
        let unique_classes: FxHashSet<EClassId> = egraph.iter_nodes().map(|(cid, _)| cid).collect();
        assert_eq!(
            unique_classes.len(),
            1,
            "post-union iter must visit exactly one canonical class id"
        );
        let total_nodes = egraph.iter_nodes().count();
        assert_eq!(
            total_nodes, 2,
            "the merged class still holds both original nodes (Const(1) + Const(2))"
        );
    }
}
