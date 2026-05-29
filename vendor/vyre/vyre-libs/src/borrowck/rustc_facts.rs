//! Producer: load rustc's `-Znll-facts` dump and run the Polonius "Naive"
//! borrow-check ruleset on the real MIR-level facts, so the borrow checker
//! applies to real Rust functions, not only the nano-subset our own front-end
//! parses, and reaches the *same* verdict rustc does.
//!
//! rustc (nightly) writes one directory of tab-separated `.facts` files per
//! function: the Polonius input relations the compiler's own borrow checker
//! consumes. We intern their string atoms (`"Start(bb0[5])"`, `"bw0"`, `"'?2"`,
//! `"_1"`) to dense per-category `u32` ids and evaluate the Naive ruleset:
//!
//! ```text
//! var_live_on_entry(V,P)    :- var_used_at(V,P)
//! var_live_on_entry(V,P)    :- var_live_on_entry(V,Q), cfg_edge(P,Q), !var_defined_at(V,P)
//! var_drop_live(V,P)        :- var_dropped_at(V,P)
//! var_drop_live(V,P)        :- var_drop_live(V,Q), cfg_edge(P,Q), !var_defined_at(V,P)
//! region_live_at(O,P)       :- use_of_var_derefs_origin(V,O),  var_live_on_entry(V,P)
//! region_live_at(O,P)       :- drop_of_var_derefs_origin(V,O), var_drop_live(V,P)
//! subset(O1,O2,P)           :- subset_base(O1,O2,P)
//! subset(O1,O3,P)           :- subset(O1,O2,P), subset(O2,O3,P)
//! subset(O1,O2,Q)           :- subset(O1,O2,P), cfg_edge(P,Q), region_live_at(O1,Q), region_live_at(O2,Q)
//! requires(O,L,P)           :- loan_issued_at(O,L,P)
//! requires(O2,L,P)          :- requires(O1,L,P), subset(O1,O2,P)
//! requires(O,L,Q)           :- requires(O,L,P), !loan_killed_at(L,P), cfg_edge(P,Q), region_live_at(O,Q)
//! loan_live_at(L,P)         :- requires(O,L,P), region_live_at(O,P)
//! errors(L,P)               :- loan_invalidated_at(P,L), loan_live_at(L,P)
//! ```
//!
//! `region_live_at` depends only on variable liveness, `subset` only on it, and
//! `requires` on both, so the relations evaluate in stages with no global mutual
//! recursion. Each stage is a monotone fixpoint - the same shape [`super::gpu`]
//! batches on the device; this module is the reference CPU verdict first.

use std::collections::{HashMap, HashSet};

/// A program point id (interned from a rustc point atom).
pub type Point = u32;
/// A loan id (interned from a rustc loan atom such as `bw0`).
pub type Loan = u32;
/// An origin/region id (interned from a rustc origin atom such as `'?2`).
pub type Origin = u32;
/// A MIR variable id (interned from a rustc variable atom such as `_1`).
pub type Var = u32;

/// rustc NLL input facts for one function, interned to dense per-category ids.
#[derive(Debug, Default, Clone)]
pub struct RustcNllFacts {
    /// Number of distinct interned program points.
    pub point_count: u32,
    /// Number of distinct interned origins (regions).
    pub origin_count: u32,
    /// Number of distinct interned MIR variables.
    pub var_count: u32,
    /// Number of distinct interned loans.
    pub loan_count: u32,
    /// Control-flow successor edges `(from, to)`.
    pub cfg_edge: Vec<(Point, Point)>,
    /// `(origin, loan, point)`: loan created at point, placed in origin.
    pub loan_issued_at: Vec<(Origin, Loan, Point)>,
    /// `(point, loan)`: an access at the point invalidates the loan.
    pub loan_invalidated_at: Vec<(Point, Loan)>,
    /// `(loan, point)`: the loan's referent is overwritten at the point.
    pub loan_killed_at: Vec<(Loan, Point)>,
    /// `(o1, o2, point)`: base region-subset relation `o1 <= o2` at the point.
    pub subset_base: Vec<(Origin, Origin, Point)>,
    /// `(var, point)`: the variable is used at the point.
    pub var_used_at: Vec<(Var, Point)>,
    /// `(var, point)`: the variable is (re)defined at the point.
    pub var_defined_at: Vec<(Var, Point)>,
    /// `(var, point)`: the variable is dropped at the point.
    pub var_dropped_at: Vec<(Var, Point)>,
    /// `(var, origin)`: a use of the variable dereferences the origin.
    pub use_of_var_derefs_origin: Vec<(Var, Origin)>,
    /// `(var, origin)`: a drop of the variable dereferences the origin.
    pub drop_of_var_derefs_origin: Vec<(Var, Origin)>,
    /// `(origin, loan)`: origin is a placeholder (a universal/free region).
    pub placeholder: Vec<(Origin, Loan)>,
    /// `(o1, o2)`: the subset `o1 <= o2` between placeholders is known/declared.
    pub known_placeholder_subset: Vec<(Origin, Origin)>,
    /// Origins that are universal (free) regions, live at every point.
    pub universal_region: Vec<Origin>,
    /// Interned point atom for each point id (for diagnostics).
    pub point_names: Vec<String>,
    /// Interned loan atom for each loan id (for diagnostics).
    pub loan_names: Vec<String>,
}

/// An NLL borrow-check error: a loan invalidated while live.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NllError {
    /// The loan that was live when invalidated.
    pub loan: Loan,
    /// The point at which the invalidating access occurred.
    pub point: Point,
}

#[derive(Default)]
struct Interner {
    ids: HashMap<String, u32>,
    names: Vec<String>,
}

impl Interner {
    fn intern(&mut self, atom: &str) -> u32 {
        if let Some(&id) = self.ids.get(atom) {
            return id;
        }
        let id = self.names.len() as u32;
        self.ids.insert(atom.to_string(), id);
        self.names.push(atom.to_string());
        id
    }
}

fn unquote(field: &str) -> &str {
    let field = field.trim();
    field.strip_prefix('"').and_then(|f| f.strip_suffix('"')).unwrap_or(field)
}

fn fields(line: &str) -> Vec<&str> {
    line.split('\t').map(unquote).collect()
}

/// Load the relations from one function's facts directory. `read(name)` returns
/// the raw text of `<name>.facts` (or "" if rustc did not emit it).
#[must_use]
pub fn load_facts(read: impl Fn(&str) -> String) -> RustcNllFacts {
    let mut points = Interner::default();
    let mut origins = Interner::default();
    let mut vars = Interner::default();
    let mut loans = Interner::default();

    let mut for_each = |name: &str, mut f: Box<dyn FnMut(Vec<&str>) + '_>| {
        let text = read(name);
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            f(fields(line));
        }
    };

    let mut cfg_edge = Vec::new();
    for_each(
        "cfg_edge",
        Box::new(|f| {
            if f.len() == 2 {
                cfg_edge.push((points.intern(f[0]), points.intern(f[1])));
            }
        }),
    );
    let mut loan_issued_at = Vec::new();
    for_each(
        "loan_issued_at",
        Box::new(|f| {
            if f.len() == 3 {
                loan_issued_at.push((origins.intern(f[0]), loans.intern(f[1]), points.intern(f[2])));
            }
        }),
    );
    let mut loan_invalidated_at = Vec::new();
    for_each(
        "loan_invalidated_at",
        Box::new(|f| {
            if f.len() == 2 {
                loan_invalidated_at.push((points.intern(f[0]), loans.intern(f[1])));
            }
        }),
    );
    let mut loan_killed_at = Vec::new();
    for_each(
        "loan_killed_at",
        Box::new(|f| {
            if f.len() == 2 {
                loan_killed_at.push((loans.intern(f[0]), points.intern(f[1])));
            }
        }),
    );
    let mut subset_base = Vec::new();
    for_each(
        "subset_base",
        Box::new(|f| {
            if f.len() == 3 {
                subset_base.push((origins.intern(f[0]), origins.intern(f[1]), points.intern(f[2])));
            }
        }),
    );
    let mut var_used_at = Vec::new();
    for_each(
        "var_used_at",
        Box::new(|f| {
            if f.len() == 2 {
                var_used_at.push((vars.intern(f[0]), points.intern(f[1])));
            }
        }),
    );
    let mut var_defined_at = Vec::new();
    for_each(
        "var_defined_at",
        Box::new(|f| {
            if f.len() == 2 {
                var_defined_at.push((vars.intern(f[0]), points.intern(f[1])));
            }
        }),
    );
    let mut var_dropped_at = Vec::new();
    for_each(
        "var_dropped_at",
        Box::new(|f| {
            if f.len() == 2 {
                var_dropped_at.push((vars.intern(f[0]), points.intern(f[1])));
            }
        }),
    );
    let mut use_of_var_derefs_origin = Vec::new();
    for_each(
        "use_of_var_derefs_origin",
        Box::new(|f| {
            if f.len() == 2 {
                use_of_var_derefs_origin.push((vars.intern(f[0]), origins.intern(f[1])));
            }
        }),
    );
    let mut drop_of_var_derefs_origin = Vec::new();
    for_each(
        "drop_of_var_derefs_origin",
        Box::new(|f| {
            if f.len() == 2 {
                drop_of_var_derefs_origin.push((vars.intern(f[0]), origins.intern(f[1])));
            }
        }),
    );
    let mut placeholder = Vec::new();
    for_each(
        "placeholder",
        Box::new(|f| {
            if f.len() == 2 {
                placeholder.push((origins.intern(f[0]), loans.intern(f[1])));
            }
        }),
    );
    let mut known_placeholder_subset = Vec::new();
    for_each(
        "known_placeholder_subset",
        Box::new(|f| {
            if f.len() == 2 {
                known_placeholder_subset.push((origins.intern(f[0]), origins.intern(f[1])));
            }
        }),
    );
    let mut universal_region = Vec::new();
    for_each(
        "universal_region",
        Box::new(|f| {
            if f.len() == 1 {
                universal_region.push(origins.intern(f[0]));
            }
        }),
    );

    RustcNllFacts {
        point_count: points.names.len() as u32,
        origin_count: origins.names.len() as u32,
        var_count: vars.names.len() as u32,
        loan_count: loans.names.len() as u32,
        cfg_edge,
        loan_issued_at,
        loan_invalidated_at,
        loan_killed_at,
        subset_base,
        var_used_at,
        var_defined_at,
        var_dropped_at,
        use_of_var_derefs_origin,
        drop_of_var_derefs_origin,
        placeholder,
        known_placeholder_subset,
        universal_region,
        point_names: points.names,
        loan_names: loans.names,
    }
}

impl RustcNllFacts {
    /// Backward variable liveness: `live(V,P)` if `V` is used at `P`, or live at
    /// a CFG successor and not defined at `P`.
    fn var_liveness(&self, seeds: &[(Var, Point)]) -> HashSet<(Var, Point)> {
        let defined: HashSet<(Var, Point)> = self.var_defined_at.iter().copied().collect();
        // preds[Q] = points P with cfg_edge(P, Q)
        let mut preds: HashMap<Point, Vec<Point>> = HashMap::new();
        for &(p, q) in &self.cfg_edge {
            preds.entry(q).or_default().push(p);
        }
        let mut live: HashSet<(Var, Point)> = seeds.iter().copied().collect();
        let mut work: Vec<(Var, Point)> = live.iter().copied().collect();
        while let Some((v, q)) = work.pop() {
            if let Some(ps) = preds.get(&q) {
                for &p in ps {
                    if !defined.contains(&(v, p)) && live.insert((v, p)) {
                        work.push((v, p));
                    }
                }
            }
        }
        live
    }

    /// `region_live_at`: an origin is live where a variable that derefs it is
    /// (use- or drop-) live; universal (free) regions are live at every point.
    fn region_live_at(&self) -> HashSet<(Origin, Point)> {
        let var_live = self.var_liveness(&self.var_used_at);
        let drop_live = self.var_liveness(&self.var_dropped_at);
        let mut region = HashSet::new();
        for &(v, o) in &self.use_of_var_derefs_origin {
            for &(lv, p) in var_live.iter().filter(|&&(lv, _)| lv == v) {
                let _ = lv;
                region.insert((o, p));
            }
        }
        for &(v, o) in &self.drop_of_var_derefs_origin {
            for &(lv, p) in drop_live.iter().filter(|&&(lv, _)| lv == v) {
                let _ = lv;
                region.insert((o, p));
            }
        }
        // Universal regions are live throughout the function.
        for &o in &self.universal_region {
            for p in 0..self.point_count {
                region.insert((o, p));
            }
        }
        region
    }

    /// `subset(O1,O2,P)`: base subsets, their transitive closure, and forward
    /// CFG propagation where both origins are live.
    fn subset_closure(
        &self,
        region_live: &HashSet<(Origin, Point)>,
        succ: &HashMap<Point, Vec<Point>>,
    ) -> HashSet<(Origin, Origin, Point)> {
        let mut subset: HashSet<(Origin, Origin, Point)> =
            self.subset_base.iter().copied().collect();
        loop {
            let mut added = Vec::new();
            let by_first: HashMap<(Origin, Point), Vec<Origin>> = {
                let mut m: HashMap<(Origin, Point), Vec<Origin>> = HashMap::new();
                for &(a, b, p) in &subset {
                    m.entry((a, p)).or_default().push(b);
                }
                m
            };
            for &(a, b, p) in &subset {
                if let Some(cs) = by_first.get(&(b, p)) {
                    for &c in cs {
                        if !subset.contains(&(a, c, p)) {
                            added.push((a, c, p));
                        }
                    }
                }
                if let Some(qs) = succ.get(&p) {
                    for &q in qs {
                        if region_live.contains(&(a, q))
                            && region_live.contains(&(b, q))
                            && !subset.contains(&(a, b, q))
                        {
                            added.push((a, b, q));
                        }
                    }
                }
            }
            if added.is_empty() {
                break;
            }
            for t in added {
                subset.insert(t);
            }
        }
        subset
    }

    /// Illegal-subset (region-outlives) errors: a derived subset between two
    /// placeholder origins that is not a known/declared placeholder subset.
    /// These are the escape/lifetime errors (rustc E0515 / E0521 and kin) that
    /// carry no loan invalidation.
    #[must_use]
    pub fn subset_errors(&self) -> Vec<(Origin, Origin)> {
        if self.point_count == 0 || self.universal_region.is_empty() {
            return Vec::new();
        }
        let placeholders: HashSet<Origin> = self.placeholder.iter().map(|&(o, _)| o).collect();
        if placeholders.is_empty() {
            return Vec::new();
        }
        let known: HashSet<(Origin, Origin)> =
            self.known_placeholder_subset.iter().copied().collect();
        let region_live = self.region_live_at();
        let succ: HashMap<Point, Vec<Point>> = {
            let mut m: HashMap<Point, Vec<Point>> = HashMap::new();
            for &(p, q) in &self.cfg_edge {
                m.entry(p).or_default().push(q);
            }
            m
        };
        let subset = self.subset_closure(&region_live, &succ);
        let mut errors: Vec<(Origin, Origin)> = subset
            .iter()
            .filter(|&&(a, b, _)| {
                a != b
                    && placeholders.contains(&a)
                    && placeholders.contains(&b)
                    && !known.contains(&(a, b))
            })
            .map(|&(a, b, _)| (a, b))
            .collect();
        errors.sort_unstable();
        errors.dedup();
        errors
    }

    /// Compute the Polonius "Naive" borrow-check errors for this function.
    #[must_use]
    pub fn nll_errors(&self) -> Vec<NllError> {
        if self.point_count == 0 || self.loan_count == 0 {
            return Vec::new();
        }
        let region_live = self.region_live_at();
        let region_live_set: HashSet<(Origin, Point)> = region_live;

        let succ: HashMap<Point, Vec<Point>> = {
            let mut m: HashMap<Point, Vec<Point>> = HashMap::new();
            for &(p, q) in &self.cfg_edge {
                m.entry(p).or_default().push(q);
            }
            m
        };

        let subset = self.subset_closure(&region_live_set, &succ);

        // requires(O,L,P): issued, via subset, and forward while live + not killed.
        let killed: HashSet<(Loan, Point)> = self.loan_killed_at.iter().copied().collect();
        let subset_by_first: HashMap<(Origin, Point), Vec<Origin>> = {
            let mut m: HashMap<(Origin, Point), Vec<Origin>> = HashMap::new();
            for &(a, b, p) in &subset {
                m.entry((a, p)).or_default().push(b);
            }
            m
        };
        let mut requires: HashSet<(Origin, Loan, Point)> = self
            .loan_issued_at
            .iter()
            .map(|&(o, l, p)| (o, l, p))
            .collect();
        loop {
            let mut added = Vec::new();
            for &(o, l, p) in &requires {
                if let Some(o2s) = subset_by_first.get(&(o, p)) {
                    for &o2 in o2s {
                        if !requires.contains(&(o2, l, p)) {
                            added.push((o2, l, p));
                        }
                    }
                }
                if !killed.contains(&(l, p)) {
                    if let Some(qs) = succ.get(&p) {
                        for &q in qs {
                            if region_live_set.contains(&(o, q)) && !requires.contains(&(o, l, q)) {
                                added.push((o, l, q));
                            }
                        }
                    }
                }
            }
            if added.is_empty() {
                break;
            }
            for t in added {
                requires.insert(t);
            }
        }

        // loan_live_at(L,P): some origin requiring L is live at P.
        let mut loan_live: HashSet<(Loan, Point)> = HashSet::new();
        for &(o, l, p) in &requires {
            if region_live_set.contains(&(o, p)) {
                loan_live.insert((l, p));
            }
        }

        // errors: invalidated while live.
        let mut errors: Vec<NllError> = self
            .loan_invalidated_at
            .iter()
            .filter(|&&(p, l)| loan_live.contains(&(l, p)))
            .map(|&(p, l)| NllError { loan: l, point: p })
            .collect();
        errors.sort_unstable_by_key(|e| (e.loan, e.point));
        errors.dedup();
        errors
    }

    /// Whether the function borrow-checks: no conflicting-borrow (loan
    /// invalidation) errors and no illegal-subset (region-outlives) errors.
    /// This is the verdict rustc's own borrow checker reaches on these facts.
    #[must_use]
    pub fn accepts(&self) -> bool {
        self.nll_errors().is_empty() && self.subset_errors().is_empty()
    }
}
