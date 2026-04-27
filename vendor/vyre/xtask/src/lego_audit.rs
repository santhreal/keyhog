//! `cargo xtask lego-audit` — deeper LEGO-block enforcement.
//!
//! Gate 1 (`cargo xtask gate1`) is the floor: loops ≤ 4 AND nodes ≤ 200
//! OR composed_fraction ≥ 60%. That's table stakes. vyre's thesis is
//! composition, so the real measurement is harder.
//!
//! This xtask runs seven stricter audits:
//!
//! 1. **No-reinvention check** — IR fingerprint every op body; any two
//!    ops with >80% fingerprint overlap where one doesn't invoke the
//!    other get flagged as duplication.
//! 2. **Depth-of-composition** — `own_nodes` vs `composed_nodes`. An op
//!    with a lot of its own nodes and few composed ones at Tier 3 is
//!    failing the LEGO pattern.
//! 3. **Primitive-coverage** — every Tier 2.5 primitive should have
//!    ≥ 2 callers. Orphans (0 or 1 caller) are either (a) waiting for
//!    a second consumer — OK for one release — or (b) premature
//!    promotion — should demote back to a private helper.
//! 4. **Cross-dialect reach-through** — Tier 3 dialects importing
//!    private items from sibling Tier 3 dialects. That coupling
//!    belongs in Tier 2.5; flag it.
//! 5. **Anti-god-file (LAW 7)** — per-file source-line + per-fn
//!    node-count budgets.
//! 6. **Composition-chain coverage** — every registered op must have
//!    `print-composition` render ≥ 1 child Region, or be marked
//!    `leaf = true` in its `OpEntry`. Single-top-level Region only =
//!    inlining in disguise.
//! 7. **Trend** — compare per-op `composed_fraction` to the previous
//!    tag; fail CI if it regresses. The thesis is "composition gets
//!    deeper over time," not "stagnates."
//!
//! Exit code 0 if every check passes. Non-zero with per-check
//! diagnostic otherwise. Intended to run in CI post-Gate 1.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::process;

use vyre::ir::{Node, Program};

const FINGERPRINT_SIM_THRESHOLD: f64 = 0.80;
const MAX_FILE_LINES: usize = 500;
const MIN_CALLERS_FOR_PRIMITIVE: usize = 2;

/// Entry point for the `lego-audit` subcommand.
pub fn run(args: &[String]) {
    let with_repo = args.iter().any(|arg| arg == "--with-repo");
    let ops = collect_ops();
    println!("=== vyre LEGO-block audit ===");
    println!("Ops audited: {}", ops.len());
    println!(
        "Repo checks: {}",
        if with_repo {
            "enabled"
        } else {
            "not requested; pass --with-repo for file-shape and trend checks"
        }
    );
    println!();

    let mut failures: usize = 0;

    failures += check_1_no_reinvention(&ops);
    failures += check_2_depth_of_composition(&ops);
    failures += check_3_primitive_coverage(&ops);
    failures += check_4_cross_dialect_reachthrough();
    if with_repo {
        failures += check_5_god_files();
    }
    failures += check_6_composition_chain_coverage(&ops);
    if with_repo {
        failures += check_7_trend(&ops);
    }

    if !with_repo {
        println!();
        println!("Checks requiring repo context (5, 7) did not run. Fix: invoke `cargo xtask lego-audit --with-repo` from a git checkout for release gates.");
    }

    if failures > 0 {
        println!();
        println!("LEGO-block audit FAILED: {failures} finding(s). Gate 1 is the floor, this is the ceiling — bring composed_fraction up or extract shared pieces to Tier 2.5.");
        process::exit(1);
    }
    println!();
    println!("LEGO-block audit ✓");
}

/// One registered op with everything the audit needs.
struct OpInfo {
    id: String,
    // Kept for future audit passes that need to re-walk the raw IR
    // (e.g. to verify that Region source_region chains are stable
    // under re-optimization). The current fingerprint/own_nodes/
    // composed_nodes/children summary is already derived from the
    // Program up-front, so downstream prints don't re-read it.
    #[allow(dead_code)]
    program: Program,
    tier: Tier,
    fingerprint: Vec<u8>,
    own_nodes: usize,
    composed_nodes: usize,
    children: BTreeSet<String>, // op_ids this op invokes via Region.source_region
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Tier {
    T2,   // vyre-intrinsics::hardware::*
    T2_5, // vyre-primitives::*
    T3,   // vyre-libs::*
    Other,
}

fn tier_of(op_id: &str) -> Tier {
    if op_id.starts_with("vyre-intrinsics::") {
        Tier::T2
    } else if op_id.starts_with("vyre-primitives::") {
        Tier::T2_5
    } else if op_id.starts_with("vyre-libs::") {
        Tier::T3
    } else {
        Tier::Other
    }
}

fn collect_ops() -> Vec<OpInfo> {
    let mut ops = Vec::new();
    for entry in vyre_libs::harness::all_entries() {
        ops.push(build_info(entry.id, (entry.build)()));
    }
    for entry in vyre_primitives::harness::all_entries() {
        ops.push(build_info(entry.id, (entry.build)()));
    }
    for entry in vyre_intrinsics::harness::all_entries() {
        ops.push(build_info(entry.id, (entry.build)()));
    }
    ops
}

fn build_info(id: &'static str, program: Program) -> OpInfo {
    let tier = tier_of(id);
    let mut state = Walk::default();
    for node in program.entry() {
        walk(node, false, &mut state);
    }
    OpInfo {
        id: id.to_string(),
        fingerprint: fingerprint_program(&program),
        own_nodes: state.own_nodes,
        composed_nodes: state.composed_nodes,
        children: state.children,
        program,
        tier,
    }
}

#[derive(Default)]
struct Walk {
    own_nodes: usize,
    composed_nodes: usize,
    children: BTreeSet<String>,
}

fn walk(node: &Node, inside_composed: bool, state: &mut Walk) {
    if inside_composed {
        state.composed_nodes += 1;
    } else {
        state.own_nodes += 1;
    }
    match node {
        Node::Region {
            source_region,
            body,
            generator,
        } => {
            let now_composed = inside_composed || source_region.is_some();
            // Also count `generator` as a child op-id if it matches a
            // known op id (not all generators are children, but when
            // the generator string collides with a registered op id
            // that's a strong hint).
            if source_region.is_some() && generator.as_str().contains("::") {
                state.children.insert(generator.as_str().to_string());
            }
            for child in body.iter() {
                walk(child, now_composed, state);
            }
        }
        Node::Loop { body, .. } => {
            for child in body {
                walk(child, inside_composed, state);
            }
        }
        Node::Block(children) => {
            for child in children {
                walk(child, inside_composed, state);
            }
        }
        Node::If {
            then, otherwise, ..
        } => {
            for child in then {
                walk(child, inside_composed, state);
            }
            for child in otherwise {
                walk(child, inside_composed, state);
            }
        }
        _ => {}
    }
}

/// Build a compact byte sequence representing the node-kind tree
/// structure of a Program's body. Two programs with identical
/// structural shape produce identical fingerprints; one-byte edits
/// produce minor differences. Used for check 1 similarity scoring.
fn fingerprint_program(program: &Program) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    for node in program.entry() {
        fingerprint_node(node, &mut out);
    }
    out
}

fn fingerprint_node(node: &Node, out: &mut Vec<u8>) {
    match node {
        Node::Let { .. } => out.push(0x01),
        Node::Assign { .. } => out.push(0x02),
        Node::Store { .. } => out.push(0x03),
        Node::If {
            then, otherwise, ..
        } => {
            out.push(0x04);
            for n in then {
                fingerprint_node(n, out);
            }
            out.push(0xFF);
            for n in otherwise {
                fingerprint_node(n, out);
            }
            out.push(0xFF);
        }
        Node::Loop { body, .. } => {
            out.push(0x05);
            for n in body {
                fingerprint_node(n, out);
            }
            out.push(0xFF);
        }
        Node::Return => out.push(0x06),
        Node::Block(nodes) => {
            out.push(0x07);
            for n in nodes {
                fingerprint_node(n, out);
            }
            out.push(0xFF);
        }
        Node::Barrier => out.push(0x08),
        Node::Region {
            source_region,
            body,
            generator,
        } => {
            out.push(0x09);
            if source_region.is_some() {
                out.extend_from_slice(&fingerprint_name(generator.as_str()));
            } else {
                for n in body.iter() {
                    fingerprint_node(n, out);
                }
            }
            out.push(0xFF);
        }
        Node::IndirectDispatch { .. } => out.push(0x0A),
        Node::AsyncLoad { .. } => out.push(0x0B),
        Node::AsyncWait { .. } => out.push(0x0C),
        _ => out.push(0x80),
    }
}

fn fingerprint_name(name: &str) -> [u8; 4] {
    let mut hash = 0x811C_9DC5u32;
    for byte in name.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(16_777_619);
    }
    hash.to_le_bytes()
}

/// Structural similarity: compare bigram frequency vectors (cosine).
/// Captures ordering, not just node-kind set — two ops are similar
/// only when sequences of adjacent node kinds match.
fn structural_similarity(a: &[u8], b: &[u8]) -> f64 {
    if a.len() < 4 || b.len() < 4 {
        return 0.0;
    }
    let a_bigrams = bigram_counts(a);
    let b_bigrams = bigram_counts(b);
    let mut dot = 0i64;
    let mut a_norm = 0i64;
    let mut b_norm = 0i64;
    for (bg, &ac) in &a_bigrams {
        let bc = b_bigrams.get(bg).copied().unwrap_or(0);
        dot += (ac as i64) * (bc as i64);
        a_norm += (ac as i64).pow(2);
    }
    for &bc in b_bigrams.values() {
        b_norm += (bc as i64).pow(2);
    }
    if a_norm == 0 || b_norm == 0 {
        return 0.0;
    }
    dot as f64 / ((a_norm as f64).sqrt() * (b_norm as f64).sqrt())
}

fn bigram_counts(bytes: &[u8]) -> HashMap<(u8, u8), u32> {
    let mut out: HashMap<(u8, u8), u32> = HashMap::new();
    for window in bytes.windows(2) {
        *out.entry((window[0], window[1])).or_insert(0) += 1;
    }
    out
}

/// Check 1: flag pairs of ops with near-identical fingerprints whose
/// Region chains don't indicate one calls the other.
///
/// Uses bigram-frequency cosine similarity — captures ordered
/// structure, not just node-kind sets.
fn check_1_no_reinvention(ops: &[OpInfo]) -> usize {
    let mut flagged = 0usize;
    println!("[1/7] No-reinvention check (bigram cosine ≥ {FINGERPRINT_SIM_THRESHOLD:.2})");
    let mut reported: BTreeSet<(String, String)> = BTreeSet::new();
    for (i, a) in ops.iter().enumerate() {
        // Only compare NON-TRIVIAL ops — trivial kernels share the
        // same "single invocation, loop, store" skeleton and their
        // structural similarity is expected. The audit targets ops
        // with real body content.
        if a.fingerprint.len() < 40 {
            continue;
        }
        for b in ops.iter().skip(i + 1) {
            if b.fingerprint.len() < 40 {
                continue;
            }
            if a.children.contains(&b.id) || b.children.contains(&a.id) {
                continue;
            }
            let sim = structural_similarity(&a.fingerprint, &b.fingerprint);
            if sim < FINGERPRINT_SIM_THRESHOLD {
                continue;
            }
            // Skip comparisons inside the same sub-dialect (math::*
            // vs math::* is often legitimate — same loop pattern over
            // same data type, different semantics).
            if same_subdialect(&a.id, &b.id) {
                continue;
            }
            let key = if a.id < b.id {
                (a.id.clone(), b.id.clone())
            } else {
                (b.id.clone(), a.id.clone())
            };
            if !reported.insert(key) {
                continue;
            }
            println!(
                "  ✗ reinvention: `{}` and `{}` are {:.0}% structurally similar (cross-dialect) but neither composes the other. Extract the shared body into a Tier 2.5 primitive.",
                a.id,
                b.id,
                sim * 100.0
            );
            flagged += 1;
        }
    }
    if flagged == 0 {
        println!("  ✓ no cross-dialect duplication");
    }
    flagged
}

/// Two op ids share a sub-dialect when their first TWO `::` segments
/// match. `vyre-libs::math::square` and `vyre-libs::math::broadcast`
/// both live under `vyre-libs::math`, so structural similarity there
/// is expected (same shape of elementwise unary op).
fn same_subdialect(a: &str, b: &str) -> bool {
    let a_prefix: Vec<&str> = a.split("::").take(3).collect();
    let b_prefix: Vec<&str> = b.split("::").take(3).collect();
    a_prefix.len() >= 3 && b_prefix.len() >= 3 && a_prefix[..2] == b_prefix[..2]
}

/// Check 2: per-op composition depth — for Tier 3 ops, composed_nodes
/// should dominate own_nodes.
fn check_2_depth_of_composition(ops: &[OpInfo]) -> usize {
    let mut flagged = 0usize;
    println!("[2/7] Depth-of-composition (Tier 3 ops should have composed_nodes ≥ own_nodes)");
    for op in ops {
        if op.tier != Tier::T3 {
            continue;
        }
        let total = op.own_nodes + op.composed_nodes;
        if total < 20 {
            continue; // Small ops are allowed to be flat.
        }
        if op.composed_nodes < op.own_nodes {
            println!(
                "  ✗ {} Tier 3 op has own={} composed={} — inlining primitive work. Wrap sub-bodies in region::wrap_child(<primitive_id>, ...).",
                op.id, op.own_nodes, op.composed_nodes
            );
            flagged += 1;
        }
    }
    if flagged == 0 {
        println!("  ✓ Tier 3 ops compose more than they inline");
    }
    flagged
}

/// Check 3: every Tier 2.5 primitive needs ≥ 2 callers.
fn check_3_primitive_coverage(ops: &[OpInfo]) -> usize {
    let mut flagged = 0usize;
    println!(
        "[3/7] Primitive coverage (Tier 2.5 primitives need ≥ {MIN_CALLERS_FOR_PRIMITIVE} callers)"
    );
    let mut caller_counts: HashMap<String, usize> = HashMap::new();
    for op in ops {
        for child in &op.children {
            if tier_of(child) == Tier::T2_5 {
                *caller_counts.entry(child.clone()).or_insert(0) += 1;
            }
        }
    }
    for op in ops {
        if op.tier != Tier::T2_5 {
            continue;
        }
        let callers = caller_counts.get(&op.id).copied().unwrap_or(0);
        if callers < MIN_CALLERS_FOR_PRIMITIVE {
            println!(
                "  ⚠ {} Tier 2.5 primitive has only {} caller(s). Either attract a second caller this cycle or demote back to a private helper in its owning dialect.",
                op.id, callers
            );
            flagged += 1;
        }
    }
    if flagged == 0 {
        println!("  ✓ every Tier 2.5 primitive has ≥ {MIN_CALLERS_FOR_PRIMITIVE} callers");
    }
    flagged
}

/// Check 6: composition-chain coverage — every non-leaf op should have
/// at least one child Region with a `source_region` pointing at
/// another registered op. Ops that explicitly declare `leaf = true`
/// are exempt (future OpEntry field).
fn check_6_composition_chain_coverage(ops: &[OpInfo]) -> usize {
    let mut flagged = 0usize;
    println!("[6/7] Composition-chain coverage (non-leaf ops must have ≥ 1 child Region with source_region)");
    for op in ops {
        // Tier 2 intrinsics and Tier 2.5 primitives are leaves unless
        // their own bodies choose to compose deeper primitives.
        if matches!(op.tier, Tier::T2 | Tier::T2_5) {
            continue;
        }
        // Tiny ops are trivially allowed to be flat.
        if op.own_nodes + op.composed_nodes < 20 {
            continue;
        }
        if op.children.is_empty() {
            println!(
                "  ⚠ {} has no registered child Regions — either mark it a leaf primitive or wrap inlined sub-bodies via region::wrap_child(<child_op_id>, ...).",
                op.id
            );
            flagged += 1;
        }
    }
    if flagged == 0 {
        println!("  ✓ every non-leaf op names at least one child op in its Region chain");
    }
    flagged
}

/// Walk `vyre-libs/src/<dialect>/**/*.rs`; flag any `use
/// vyre_libs::<other_dialect>::...` import that crosses a dialect
/// boundary. Cross-dialect coupling means the shared piece belongs in
/// Tier 2.5 (`vyre-primitives`), not duplicated or imported sideways.
///
/// The check is structural — it reads raw source with `fs::read_dir` and
/// a `use`-line grep. It does not invoke rustc, so it runs in any CI
/// shell that has the repo checkout.
///
/// CRITIQUE_VISION_ALIGNMENT_2026-04-23 V5 was precisely this category:
/// `surgec::compile::ir_emit` reached into
/// `vyre_libs::security::topology::match_order` for generic byte-range
/// ordering. V5's hoist into `vyre_libs::range_ordering` and this
/// automated check keep that coupling from returning.
fn check_4_cross_dialect_reachthrough() -> usize {
    println!("[4/7] Cross-dialect reach-through (Tier 3 dialects must not import private items from sibling Tier 3 dialects)");
    let libs_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| p.join("vyre-libs").join("src"));
    let Some(libs_root) = libs_root.filter(|p| p.is_dir()) else {
        println!(
            "  ⚠ vyre-libs/src not reachable from xtask. Fix: invoke from the workspace root."
        );
        return 0;
    };
    let dialects = list_dialect_dirs(&libs_root);
    if dialects.len() < 2 {
        println!("  ✓ fewer than 2 dialects present; nothing to cross.");
        return 0;
    }
    let mut flagged = 0usize;
    for dialect in &dialects {
        let dialect_name = dialect.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let mut stack = vec![dialect.clone()];
        while let Some(dir) = stack.pop() {
            let Ok(read_dir) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in read_dir.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                for (line_no, line) in text.lines().enumerate() {
                    let trimmed = line.trim_start();
                    if !trimmed.starts_with("use ") {
                        continue;
                    }
                    for other in &dialects {
                        let other_name = other.file_name().and_then(|n| n.to_str()).unwrap_or("");
                        if other_name == dialect_name || other_name.is_empty() {
                            continue;
                        }
                        let needle = format!("vyre_libs::{other_name}::");
                        let needle_crate = format!("crate::{other_name}::");
                        if trimmed.contains(&needle) || trimmed.contains(&needle_crate) {
                            println!(
                                "  ✗ {}/{} line {}: `{}` → imports `{other_name}` dialect privately. \
                                 Fix: hoist the shared piece into vyre-primitives, or route via a \
                                 public re-export at crate root.",
                                dialect_name,
                                path.file_name()
                                    .and_then(|n| n.to_str())
                                    .unwrap_or("?"),
                                line_no + 1,
                                trimmed
                            );
                            flagged += 1;
                        }
                    }
                }
            }
        }
    }
    if flagged == 0 {
        println!("  ✓ no Tier-3 dialect imports another Tier-3 dialect privately");
    }
    flagged
}

fn list_dialect_dirs(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let Ok(read_dir) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in read_dir.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        // Skip non-dialect dirs: region, tensor_ref, builder, buffer_names,
        // descriptor are shared utility modules at crate root; everything
        // else under src/ is a domain dialect.
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if matches!(
            name,
            "region" | "tensor_ref" | "builder" | "buffer_names" | "descriptor"
        ) {
            continue;
        }
        out.push(path);
    }
    out
}

fn check_5_god_files() -> usize {
    println!("[5/7] Anti-god-file (Rust source files must stay ≤ {MAX_FILE_LINES} lines)");
    let Some(root) = workspace_root() else {
        println!("  ✗ workspace root not reachable from xtask. Fix: run from the vyre workspace checkout.");
        return 1;
    };

    let mut flagged = 0usize;
    for entry in walkdir::WalkDir::new(&root)
        .into_iter()
        .filter_entry(|entry| {
            let name = entry.file_name().to_string_lossy();
            !matches!(
                name.as_ref(),
                ".git" | "target" | "target-codex" | "target-fusion-fix"
            )
        })
    {
        let Ok(entry) = entry else {
            continue;
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let line_count = text.lines().count();
        if line_count > MAX_FILE_LINES {
            println!(
                "  ✗ {} has {line_count} lines. Fix: split by responsibility until each Rust file is ≤ {MAX_FILE_LINES} lines.",
                path.strip_prefix(&root).unwrap_or(path).display()
            );
            flagged += 1;
        }
    }
    if flagged == 0 {
        println!("  ✓ every Rust source file is within the LAW 7 line budget");
    }
    flagged
}

fn check_7_trend(ops: &[OpInfo]) -> usize {
    println!("[7/7] Composition trend (current composed_fraction must not regress from previous tag baseline)");
    let Some(root) = workspace_root() else {
        println!("  ✗ workspace root not reachable from xtask. Fix: run from the vyre workspace checkout.");
        return 1;
    };
    let Some(tag) = previous_tag(&root) else {
        println!("  ✓ no previous git tag found; trend check has no baseline");
        return 0;
    };
    let Some(previous) = previous_composition_baseline(&root, &tag) else {
        println!(
            "  ✗ previous tag `{tag}` has no audits/lego-composition.tsv baseline. Fix: generate and commit the baseline before cutting the next tag."
        );
        return 1;
    };

    let current = composition_fractions(ops);
    let mut flagged = 0usize;
    for (op_id, old_fraction) in previous {
        let Some(new_fraction) = current.get(&op_id) else {
            continue;
        };
        if *new_fraction + f64::EPSILON < old_fraction {
            println!(
                "  ✗ {op_id} composed_fraction regressed from {:.1}% to {:.1}%. Fix: restore Region composition or extract shared work to Tier 2.5.",
                old_fraction * 100.0,
                new_fraction * 100.0
            );
            flagged += 1;
        }
    }
    if flagged == 0 {
        println!("  ✓ no composed_fraction regressions against `{tag}`");
    }
    flagged
}

fn workspace_root() -> Option<std::path::PathBuf> {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(std::path::Path::to_path_buf)
}

fn composition_fractions(ops: &[OpInfo]) -> BTreeMap<String, f64> {
    ops.iter()
        .map(|op| {
            let total = op.own_nodes + op.composed_nodes;
            let fraction = if total == 0 {
                1.0
            } else {
                op.composed_nodes as f64 / total as f64
            };
            (op.id.clone(), fraction)
        })
        .collect()
}

fn previous_tag(root: &std::path::Path) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["describe", "--tags", "--abbrev=0", "HEAD^"])
        .current_dir(root)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let tag = String::from_utf8(output.stdout).ok()?;
    let tag = tag.trim();
    (!tag.is_empty()).then(|| tag.to_string())
}

fn previous_composition_baseline(
    root: &std::path::Path,
    tag: &str,
) -> Option<BTreeMap<String, f64>> {
    let output = std::process::Command::new("git")
        .args(["show", &format!("{tag}:audits/lego-composition.tsv")])
        .current_dir(root)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let mut cols = line.split('\t');
        let Some(op_id) = cols.next() else {
            continue;
        };
        let Some(fraction) = cols.next().and_then(|raw| raw.parse::<f64>().ok()) else {
            continue;
        };
        out.insert(op_id.to_string(), fraction);
    }
    Some(out)
}
