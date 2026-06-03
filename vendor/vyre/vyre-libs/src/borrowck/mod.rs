//! Front-end-agnostic borrow-check engine.
//!
//! This module is the borrow checker's brain and its stable contract. The
//! [`BorrowFacts`] IR is the neutral input that any front-end produces; the
//! [`analyze`] engine consumes only that IR and never depends on a parser,
//! resolver, or rustc. That separation is what lets the borrow checker run on
//! real repos today (a rustc adapter produces facts) and run standalone later
//! (our own front-end produces the same facts) without the engine changing.
//!
//! The analysis is a control-flow dataflow (NLL loan liveness) over the CFG, so
//! it is correct across arbitrary control flow (branches included) and is the
//! fixpoint the downstream GPU backend evaluates batched across a whole crate. The
//! fact schema is modeled on the Polonius input facts and is extended over time
//! (regions, moves, ...) without breaking the engine's dependents.
//!
//! The CPU [`analyze`] engine is the reference; [`gpu::analyze_batched`]
//! computes the identical verdict on a device, batched across all loans.

pub mod gpu;
pub mod rustc_facts;

/// A program point in a function's control-flow graph (`0..point_count`).
pub type Point = u32;
/// A loan: one `&`/`&mut` borrow, an index into the per-loan fact tables.
pub type Loan = u32;
/// A borrowable place (e.g. a variable), identified by the producer.
pub type Place = u32;

/// Whether a loan is shared (`&`) or mutable (`&mut`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LoanKind {
    /// A shared `&` borrow.
    Shared,
    /// A mutable `&mut` borrow.
    Mut,
}

/// Neutral borrow-check facts for one function: the stable contract between any
/// front-end producer and the [`analyze`] engine.
///
/// Per-loan tables are parallel arrays indexed by [`Loan`]. The schema is
/// deliberately small and append-only; new relations (regions, moves, place
/// trees) are added as new fields without changing existing consumers.
#[derive(Clone, Debug, Default)]
pub struct BorrowFacts {
    /// Program points are `0..point_count`.
    pub point_count: u32,
    /// Control-flow successor edges `(from, to)`.
    pub cfg_edges: Vec<(Point, Point)>,
    /// Place borrowed by each loan.
    pub loan_place: Vec<Place>,
    /// Kind of each loan.
    pub loan_kind: Vec<LoanKind>,
    /// Point at which each loan is issued (its borrow expression).
    pub loan_issued_at: Vec<Point>,
    /// Source byte offset of each loan, for diagnostics.
    pub loan_offset: Vec<u32>,
    /// `(loan, point)`: the loan's reference is used at this point.
    pub loan_used_at: Vec<(Loan, Point)>,
}

impl BorrowFacts {
    /// Number of loans in the fact set.
    #[must_use]
    pub fn loan_count(&self) -> usize {
        self.loan_place.len()
    }
}

/// The kind of a detected borrow conflict.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConflictKind {
    /// Two `&mut` borrows of one place are live at once (rustc E0499).
    TwoMutable,
    /// A `&mut` and a `&` borrow of one place are live at once (rustc E0502).
    MutableAndShared,
}

/// A borrow conflict between two loans.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Conflict {
    /// The earlier-issued loan.
    pub first: Loan,
    /// The later-issued loan (the access that triggers the error).
    pub second: Loan,
    /// Source byte offset of the later loan.
    pub offset: u32,
    /// What kind of conflict this is.
    pub kind: ConflictKind,
}

/// Analyze borrow facts and return every conflicting-borrow violation
/// (rustc E0499 / E0502).
///
/// NLL loan liveness is computed as reachability over the CFG: a loan is live at
/// a point when a use of it is forward-reachable from that point and the point
/// is reachable from the loan's issue. Two loans of the same place conflict when
/// one is live at the other's issue point and at least one is mutable. This is
/// correct for arbitrary control flow; borrows confined to mutually exclusive
/// branches do not conflict, while borrows live across a branch point do.
#[must_use]
pub fn analyze(facts: &BorrowFacts) -> Vec<Conflict> {
    let n = facts.point_count as usize;
    let loans = facts.loan_count();
    if loans < 2 || n == 0 {
        return Vec::new();
    }

    let mut succ: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut pred: Vec<Vec<usize>> = vec![Vec::new(); n];
    for &(a, b) in &facts.cfg_edges {
        let (a, b) = (a as usize, b as usize);
        if a < n && b < n {
            succ[a].push(b);
            pred[b].push(a);
        }
    }

    let words = loans.div_ceil(64);
    // Per-point loan bitsets seeding the two dataflows.
    let mut use_seed = vec![vec![0u64; words]; n];
    for &(l, p) in &facts.loan_used_at {
        if (l as usize) < loans && (p as usize) < n {
            set_bit(&mut use_seed[p as usize], l as usize);
        }
    }
    let mut issue_seed = vec![vec![0u64; words]; n];
    for l in 0..loans {
        let p = facts.loan_issued_at[l] as usize;
        if p < n {
            set_bit(&mut issue_seed[p], l);
        }
    }

    // Two monotone bitset fixpoints (the exact form the downstream GPU backend
    // evaluates, batched): `backward[p]` holds loans whose use is forward-
    // reachable from p, `forward[p]` holds loans whose issue reaches p. A loan
    // is live at p iff it is in both.
    let backward = fixpoint(&succ, &use_seed, n, words);
    let forward = fixpoint(&pred, &issue_seed, n, words);

    let mut conflicts = Vec::new();
    for a in 0..loans {
        for b in (a + 1)..loans {
            if facts.loan_place[a] != facts.loan_place[b] {
                continue;
            }
            let a_mut = facts.loan_kind[a] == LoanKind::Mut;
            let b_mut = facts.loan_kind[b] == LoanKind::Mut;
            if !(a_mut || b_mut) {
                continue;
            }
            let issue_a = facts.loan_issued_at[a] as usize;
            let issue_b = facts.loan_issued_at[b] as usize;
            // `a` is live at `b`'s issue iff issue_a reaches it and a use of `a`
            // is still reachable from there (and symmetrically for `b`).
            let a_live_at_b =
                issue_b < n && test_bit(&forward[issue_b], a) && test_bit(&backward[issue_b], a);
            let b_live_at_a =
                issue_a < n && test_bit(&forward[issue_a], b) && test_bit(&backward[issue_a], b);
            let overlap = a_live_at_b || b_live_at_a;
            if overlap {
                let (first, second) = if issue_a <= issue_b { (a, b) } else { (b, a) };
                conflicts.push(Conflict {
                    first: first as Loan,
                    second: second as Loan,
                    offset: facts.loan_offset[second],
                    kind: if a_mut && b_mut {
                        ConflictKind::TwoMutable
                    } else {
                        ConflictKind::MutableAndShared
                    },
                });
            }
        }
    }
    conflicts
}

/// Monotone bitset dataflow fixpoint:
/// `out[p] = seed[p] | union over q in adj[p] of out[q]`, iterated with a
/// worklist until stable. With `adj = succ` this is backward liveness (use
/// reachability); with `adj = pred` it is forward issue reachability. The set
/// lattice is finite and the transfer monotone, so it terminates on any CFG
/// (loops included). This is the kernel the downstream GPU backend evaluates.
fn fixpoint(adj: &[Vec<usize>], seed: &[Vec<u64>], n: usize, words: usize) -> Vec<Vec<u64>> {
    // dependents[q] = points p that read out[q] (i.e. q in adj[p]).
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (p, edges) in adj.iter().enumerate() {
        for &q in edges {
            dependents[q].push(p);
        }
    }
    let mut out = seed.to_vec();
    let mut work: Vec<usize> = (0..n).collect();
    let mut queued = vec![true; n];
    while let Some(p) = work.pop() {
        queued[p] = false;
        let mut next = seed[p].clone();
        for &q in &adj[p] {
            or_into(&mut next, &out[q], words);
        }
        if next != out[p] {
            out[p] = next;
            for &d in &dependents[p] {
                if !queued[d] {
                    queued[d] = true;
                    work.push(d);
                }
            }
        }
    }
    out
}

#[inline]
fn set_bit(set: &mut [u64], bit: usize) {
    set[bit / 64] |= 1u64 << (bit % 64);
}

#[inline]
fn test_bit(set: &[u64], bit: usize) -> bool {
    (set[bit / 64] >> (bit % 64)) & 1 == 1
}

#[inline]
fn or_into(dst: &mut [u64], src: &[u64], words: usize) {
    for i in 0..words {
        dst[i] |= src[i];
    }
}
