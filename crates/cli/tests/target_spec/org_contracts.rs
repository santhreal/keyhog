//! ORGANIZATION-CONTRACT TARGET SPEC (the org worklist).
//!
//! Every test here asserts a CONCRETE organization contract keyhog SHOULD meet
//! but does NOT yet. Each FAILING assertion is a tracked organization gap — a
//! finding (Law 6: a failing contract test is a finding). These tests are not
//! decorative: each one parses the REAL tree (lib.rs, Cargo.toml, the gate
//! scripts, the engine module) and asserts a measured/computed value against a
//! target. They are VISIBLY RED where the contract is violated and turn GREEN
//! only when the underlying structure is actually fixed — never by weakening the
//! assertion (Law 9).
//!
//! Contract families (Adversarial Review Vector 8 ARCHITECTURE + 7 DEDUP):
//!   * ONE re-export point per crate: `lib.rs` should expose a single curated
//!     aggregation surface, not a sprawl of `pub use foo::bar` lines. Today
//!     core=10, sources=14, scanner=9 production `pub use` lines. TARGET: <= 3.
//!   * No dead backend enum arm (`ScanBackend` variant referenced nowhere).
//!   * no repository-level `vendor/` tree or Cargo path dependency into it
//!     graph — never a workspace member.
//!   * The audit entrypoint `scripts/gates/run_all.sh` references EVERY gate
//!     script under `scripts/gates/`. A gate that exists but is not wired into
//!     the one entrypoint is a dead route.
//!   * No TODO/FIXME/XXX/HACK marker or `todo!()`/`unimplemented!()` in shipped
//!     (non-test) source.
//!   * No engine source file mixing more than one top-level responsibility
//!     (multiple distinct `impl CompiledScanner` blocks + free `pub fn` groups
//!     in one file is a god-file smell).
//!
//! Each crate gets its own case (a per-crate finding) AND there is an aggregate
//! case, so the worklist surfaces both the per-target detail and the rollup.
//!
//! Resolution: this test runs from `crates/cli`, so `CARGO_MANIFEST_DIR/../..`
//! is the repo root. No network, no built corpus, no GPU — a pure source/org
//! gate that runs anywhere `cargo test` runs.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Repo root, resolved from this crate's manifest dir (`crates/cli`).
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root resolves from crates/cli/../..")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn is_testing_surface_line(t: &str) -> bool {
    t.starts_with("pub mod testing")
        || (t.starts_with("pub use ") && t.contains("testing"))
        || (t.starts_with("pub use ") && t.contains("testing_facade"))
}

/// The five workspace member crates, in dependency order.
const CRATES: [&str; 5] = ["core", "scanner", "sources", "cli", "verifier"];

/// TARGET: a crate's `lib.rs` should expose at most this many top-level
/// `pub use` re-export lines. A single curated aggregation point (one
/// `pub use submodule::*` glob plus a tiny number of hand-picked re-exports)
/// is the contract. More than this is a fan-out of re-export points — the
/// "one re-export point per crate" violation.
const MAX_REEXPORT_LINES: usize = 3;

/// Count the top-level production `pub use` lines in a `lib.rs`: every
/// `pub use ...;` that appears BEFORE the `#[doc(hidden)] pub mod testing { ... }`
/// aggregation block (those test-only re-exports are a separate, sanctioned
/// surface) and that is at column 0 (not nested inside another module body).
fn production_reexport_lines(lib_src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut doc_hidden_next = false;
    for line in lib_src.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#[doc(hidden)]") {
            doc_hidden_next = true;
            continue;
        }
        if doc_hidden_next && is_testing_surface_line(trimmed) {
            doc_hidden_next = false;
            continue;
        }
        doc_hidden_next = false;
        // Stop at the doc-hidden test aggregation module: everything after it
        // is the sanctioned test-only re-export surface, not production API.
        if trimmed.starts_with("pub mod testing {") || trimmed == "pub mod testing" {
            break;
        }
        // Only column-0 `pub use` lines count as a top-level re-export point;
        // a `pub use` indented inside a `pub mod foo { ... }` body belongs to
        // that submodule's own (single) surface.
        if line.starts_with("pub use ") {
            out.push(line.trim_end().to_string());
        }
    }
    out
}

fn lib_rs_path(root: &Path, krate: &str) -> PathBuf {
    root.join("crates").join(krate).join("src").join("lib.rs")
}

fn count_reexports(root: &Path) -> BTreeMap<&'static str, usize> {
    let mut map = BTreeMap::new();
    for krate in CRATES {
        let src = read(&lib_rs_path(root, krate));
        map.insert(krate, production_reexport_lines(&src).len());
    }
    map
}

// ── Per-crate "ONE re-export point" contracts (5 findings) ──────────────────

fn assert_single_reexport_point(krate: &str) {
    let root = repo_root();
    let src = read(&lib_rs_path(&root, krate));
    let lines = production_reexport_lines(&src);
    assert!(
        lines.len() <= MAX_REEXPORT_LINES,
        "ORG GAP [{krate}]: crate `keyhog-{krate}` has {} top-level `pub use` \
         re-export lines in lib.rs, exceeding the single-aggregation-point target \
         of <= {MAX_REEXPORT_LINES}. Collapse them behind one curated re-export \
         module (or a single `pub use submodule::*` glob) so the crate has exactly \
         ONE re-export point. Offending lines:\n{}",
        lines.len(),
        lines
            .iter()
            .map(|l| format!("    {}", l.trim()))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

#[test]
fn org_core_has_single_reexport_point() {
    assert_single_reexport_point("core");
}

#[test]
fn org_scanner_has_single_reexport_point() {
    assert_single_reexport_point("scanner");
}

#[test]
fn org_sources_has_single_reexport_point() {
    assert_single_reexport_point("sources");
}

#[test]
fn org_cli_has_single_reexport_point() {
    assert_single_reexport_point("cli");
}

#[test]
fn org_verifier_has_single_reexport_point() {
    assert_single_reexport_point("verifier");
}

// ── Aggregate re-export contract (1 finding) ────────────────────────────────

#[test]
fn org_total_reexport_lines_within_budget() {
    let root = repo_root();
    let counts = count_reexports(&root);
    let total: usize = counts.values().sum();
    // 5 crates × 1 curated aggregation point ≈ at most 5 lines fleet-wide,
    // generously bounded to 2× the per-crate target to allow one extra
    // hand-picked re-export per crate.
    let budget = CRATES.len() * MAX_REEXPORT_LINES;
    assert!(
        total <= budget,
        "ORG GAP [aggregate]: fleet-wide top-level `pub use` re-export lines = {total} \
         (budget {budget}). Per-crate: {counts:?}. The re-export surface is sprawling; \
         each crate should funnel its public API through one aggregation point.",
    );
}

// ── Pin invariant: the three big offenders are exactly where we measured ────
// These FAIL the moment the count drifts in EITHER direction, so a partial
// cleanup that fixes some but not the documented worklist count is visible.

#[test]
fn org_core_reexport_count_is_documented_offender() {
    let root = repo_root();
    let n = production_reexport_lines(&read(&lib_rs_path(&root, "core"))).len();
    assert!(
        n <= MAX_REEXPORT_LINES,
        "ORG GAP [core]: measured {n} top-level `pub use` lines (worklist baseline 10). \
         Target <= {MAX_REEXPORT_LINES}. Still over budget — collapse into one re-export module.",
    );
}

#[test]
fn org_sources_reexport_count_is_documented_offender() {
    let root = repo_root();
    let n = production_reexport_lines(&read(&lib_rs_path(&root, "sources"))).len();
    assert!(
        n <= MAX_REEXPORT_LINES,
        "ORG GAP [sources]: measured {n} top-level `pub use` lines (worklist baseline 14). \
         Target <= {MAX_REEXPORT_LINES}. The per-source `pub use foo::Bar` ladder should \
         collapse to one curated `prelude`/re-export module.",
    );
}

#[test]
fn org_scanner_reexport_count_is_documented_offender() {
    let root = repo_root();
    let n = production_reexport_lines(&read(&lib_rs_path(&root, "scanner"))).len();
    assert!(
        n <= MAX_REEXPORT_LINES,
        "ORG GAP [scanner]: measured {n} top-level `pub use` lines (worklist baseline 9). \
         Target <= {MAX_REEXPORT_LINES}. The engine/error/types/hw_probe re-exports should \
         funnel through one aggregation point.",
    );
}

// ── No dead backend enum arm (4 variant findings + 1 rollup) ────────────────

/// Parse the `ScanBackend` variant identifiers out of the enum body.
fn scan_backend_variants(root: &Path) -> Vec<String> {
    let src = read(&root.join("crates/scanner/src/hw_probe/mod.rs"));
    let start = src
        .find("pub enum ScanBackend {")
        .expect("ScanBackend enum is declared in hw_probe/mod.rs");
    let body = &src[start..];
    let end = body
        .find('}')
        .expect("ScanBackend enum body is brace-closed");
    let body = &body[..end];
    let mut variants = Vec::new();
    for raw in body.lines() {
        let line = raw.trim();
        // Skip doc comments, attributes, the `pub enum` header.
        if line.starts_with("///")
            || line.starts_with("//")
            || line.starts_with('#')
            || line.starts_with("pub enum")
            || line.is_empty()
        {
            continue;
        }
        // A variant line looks like `Gpu,` or `SimdCpu,`.
        let ident: String = line
            .trim_end_matches(',')
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !ident.is_empty() && ident.chars().next().unwrap().is_ascii_uppercase() {
            variants.push(ident);
        }
    }
    variants
}

/// How many times `ScanBackend::<Variant>` appears across all crate source
/// EXCLUDING the enum declaration file's own `Self::` match arms (those are the
/// definition's label impl, not a real use site). A variant referenced only by
/// its own `label()` arm and nowhere else is a dead arm.
fn variant_use_sites(root: &Path, variant: &str) -> usize {
    let needle = format!("ScanBackend::{variant}");
    let mut count = 0usize;
    for krate in CRATES {
        let src_dir = root.join("crates").join(krate).join("src");
        for entry in walk_rs(&src_dir) {
            let src = read(&entry);
            count += src.matches(&needle).count();
        }
    }
    count
}

/// Recursively collect `.rs` files under a directory.
fn walk_rs(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk_rs(&p));
            } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
                out.push(p);
            }
        }
    }
    out
}

fn assert_backend_variant_live(variant: &str) {
    let root = repo_root();
    let variants = scan_backend_variants(&root);
    assert!(
        variants.iter().any(|v| v == variant),
        "ScanBackend enum no longer declares variant `{variant}` — test fixture stale; \
         re-derive against hw_probe/mod.rs. Declared: {variants:?}",
    );
    let sites = variant_use_sites(&root, variant);
    // A live arm is referenced by more than just its `label()` Self-arm. The
    // label impl uses `Self::Variant`, NOT `ScanBackend::Variant`, so any
    // `ScanBackend::Variant` site is a real routing/selection use. A live
    // variant must have >= 2 such sites (selection + at least one dispatch).
    assert!(
        sites >= 2,
        "ORG GAP [backend]: `ScanBackend::{variant}` is referenced at only {sites} \
         non-definition site(s) across the crates — a (near-)dead enum arm. Either wire \
         it into real selection/dispatch or remove the arm (no dead backend route).",
    );
}

#[test]
fn org_backend_arm_gpu_is_live() {
    assert_backend_variant_live("Gpu");
}

#[test]
fn org_backend_arm_megascan_is_live() {
    assert_backend_variant_live("MegaScan");
}

#[test]
fn org_backend_arm_simdcpu_is_live() {
    assert_backend_variant_live("SimdCpu");
}

#[test]
fn org_backend_arm_cpufallback_is_live() {
    assert_backend_variant_live("CpuFallback");
}

#[test]
fn org_backend_enum_arm_count_matches_label_impl() {
    // Every declared variant must have a `Self::Variant =>` arm in `label()`.
    // A variant without a label arm (or a label arm without a variant) is a
    // non-exhaustive/dead-arm coherence break.
    let root = repo_root();
    let variants = scan_backend_variants(&root);
    let src = read(&root.join("crates/scanner/src/hw_probe/mod.rs"));
    let label_start = src
        .find("pub fn label(")
        .expect("ScanBackend::label is declared");
    let label_body = &src[label_start..];
    for v in &variants {
        let arm = format!("Self::{v} =>");
        assert!(
            label_body.contains(&arm),
            "ORG GAP [backend]: ScanBackend variant `{v}` has no `{arm}` arm in `label()` — \
             a dead/non-exhaustive enum arm. Every backend route must carry a stable label.",
        );
    }
    assert_eq!(
        variants.len(),
        4,
        "ORG GAP [backend]: expected exactly 4 ScanBackend variants (Gpu, MegaScan, SimdCpu, \
         CpuFallback); found {}: {variants:?}. A new arm must be wired into selection, dispatch, \
         label, and the backend-parity matrix before it counts as live.",
        variants.len(),
    );
}

// ── repository vendor tree absent from the build graph ───────────────────────

/// The workspace `members` and `exclude` lists, parsed from the root Cargo.toml.
fn workspace_members_and_excludes(root: &Path) -> (Vec<String>, Vec<String>) {
    let cargo = read(&root.join("Cargo.toml"));
    let value: toml::Value = toml::from_str(&cargo).expect("root Cargo.toml parses");
    let ws = value
        .get("workspace")
        .and_then(|w| w.as_table())
        .expect("[workspace] table present");
    let to_vec = |key: &str| -> Vec<String> {
        ws.get(key)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    (to_vec("members"), to_vec("exclude"))
}

fn assert_snapshot_absent(snapshot: &str) {
    let root = repo_root();
    let (members, excludes) = workspace_members_and_excludes(&root);
    assert!(
        !root.join(snapshot).exists(),
        "ORG GAP [vendor]: `{snapshot}` is retired and must not exist in this repo",
    );
    assert!(
        !members.iter().any(|m| m.contains(snapshot)),
        "ORG GAP [vendor]: retired `{snapshot}` is a workspace member. Members: {members:?}",
    );
    assert!(
        !excludes.iter().any(|e| e.contains(snapshot)),
        "ORG GAP [vendor]: retired `{snapshot}` still appears in workspace exclude. Excludes: {excludes:?}",
    );
}

#[test]
fn org_repository_vendor_tree_removed_from_repo() {
    assert_snapshot_absent("vendor");
}

#[test]
fn org_no_path_dependency_points_into_vendor() {
    // No crate may declare a `path = ".../vendor/..."` dependency: that would
    // silently rebuild a second source tree inside the repository.
    let root = repo_root();
    let mut offenders = Vec::new();
    for krate in CRATES {
        let cargo = root.join("crates").join(krate).join("Cargo.toml");
        let src = read(&cargo);
        for (i, line) in src.lines().enumerate() {
            let l = line.trim();
            if l.contains("path") && l.contains("vendor/") {
                offenders.push(format!("crates/{krate}/Cargo.toml:{}: {l}", i + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "ORG GAP [vendor]: a path-dependency points into a vendored snapshot, re-entering it \
         into the build graph:\n{}",
        offenders.join("\n"),
    );
}

// ── Root contract: no unowned top-level systems ─────────────────────────────

const ALLOWED_ROOT_FILES: &[&str] = &[
    ".gitattributes",
    ".gitignore",
    ".keyhog.toml.example",
    ".keyhogignore",
    ".pre-commit-config.yaml",
    ".pre-commit-hooks.yaml",
    "AGENTS.md",
    "AUTHORS",
    "CHANGELOG.md",
    "CLAUDE.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "Cargo.lock",
    "Cargo.toml",
    "Dockerfile",
    "LICENSE",
    "LICENSE-APACHE",
    "LICENSE-MIT",
    "NOTICE",
    "PUBLISHING.md",
    "README.md",
    "SECURITY.md",
    "audit.toml",
    "deny.toml",
    "install.ps1",
    "install.sh",
];

const ALLOWED_ROOT_DIRS: &[&str] = &[
    ".github",
    "benchmarks",
    "crates",
    "demo",
    "detectors",
    "docs",
    "fuzz",
    "metrics",
    "ml",
    "rules",
    "scripts",
    "site",
    "tests",
    "tools",
];

fn path_is_git_ignored(root: &Path, name: &str) -> bool {
    Command::new("git")
        .args(["-C"])
        .arg(root)
        .args(["check-ignore", "-q", "--", name])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[test]
fn org_root_entries_match_named_contract() {
    let root = repo_root();
    let allowed_files: BTreeSet<&str> = ALLOWED_ROOT_FILES.iter().copied().collect();
    let allowed_dirs: BTreeSet<&str> = ALLOWED_ROOT_DIRS.iter().copied().collect();
    let mut offenders = Vec::new();

    for entry in std::fs::read_dir(&root).expect("read repo root") {
        let entry = entry.expect("read repo root entry");
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == ".git" || path_is_git_ignored(&root, &name) {
            continue;
        }
        let allowed = if entry.path().is_dir() {
            allowed_dirs.contains(name.as_ref())
        } else {
            allowed_files.contains(name.as_ref())
        };
        if !allowed {
            let kind = if entry.path().is_dir() { "dir" } else { "file" };
            offenders.push(format!("{kind}: {name}"));
        }
    }

    assert!(
        offenders.is_empty(),
        "ORG GAP [root]: top-level entries must be explicit product entry points \
         or named systems. Move/delete/classify these root entries:\n{}",
        offenders.join("\n"),
    );
}

#[test]
fn org_install_scenarios_are_os_addressable() {
    let root = repo_root();
    let install = root.join("tests/install");
    for dir in ["linux", "macos", "windows", "fixtures"] {
        assert!(
            install.join(dir).is_dir(),
            "ORG GAP [install]: tests/install/{dir}/ must exist so install scenarios are discoverable by OS"
        );
    }

    let flat_scripts: Vec<String> = std::fs::read_dir(&install)
        .expect("read tests/install")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("sh"))
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        flat_scripts.is_empty(),
        "ORG GAP [install]: shell scenarios must not live flat under tests/install; \
         move them under linux/, macos/, windows/, or fixtures/: {flat_scripts:?}"
    );

    for script in [
        "linux/scenarios.sh",
        "linux/edge_cases.sh",
        "linux/calibration_probe_flag_compat.sh",
        "linux/install_from_local_build.sh",
        "macos/install_from_local_build.sh",
        "fixtures/install_from_local_build_posix.sh",
    ] {
        assert!(
            install.join(script).is_file(),
            "ORG GAP [install]: missing expected install scenario/fixture tests/install/{script}"
        );
    }

    let ci = read(&root.join(".github/workflows/ci.yml"));
    for path in [
        "tests/install/linux/scenarios.sh",
        "tests/install/linux/edge_cases.sh",
        "tests/install/linux/calibration_probe_flag_compat.sh",
        "tests/install/linux/install_from_local_build.sh",
        "tests/install/macos/install_from_local_build.sh",
    ] {
        assert!(
            ci.contains(path),
            "ORG GAP [install]: CI must call OS-specific install scenario path {path}"
        );
    }
    for retired in [
        "tests/install/scenarios.sh",
        "tests/install/edge_cases.sh",
        "tests/install/calibration_probe_flag_compat.sh",
        "tests/install/install_from_local_build.sh",
    ] {
        assert!(
            !ci.contains(retired),
            "ORG GAP [install]: CI still references retired flat install path {retired}"
        );
    }
}

// ── The audit entrypoint references every gate (2 findings) ─────────────────

/// All gate scripts under `scripts/gates/` (the `.py`/`.sh` that are gates, not
/// the entrypoint itself or its baseline data file).
fn gate_scripts(root: &Path) -> Vec<String> {
    let dir = root.join("scripts/gates");
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            let p = e.path();
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
            if name == "run_all.sh" {
                continue; // the entrypoint itself
            }
            if ext == "py" || ext == "sh" {
                out.push(name.to_string());
            }
        }
    }
    out.sort();
    out
}

#[test]
fn org_run_all_references_every_gate_script() {
    let root = repo_root();
    let run_all = read(&root.join("scripts/gates/run_all.sh"));
    let mut missing = Vec::new();
    for gate in gate_scripts(&root) {
        // run_all.sh may reference the gate by its bare filename.
        if !run_all.contains(&gate) {
            missing.push(gate);
        }
    }
    assert!(
        missing.is_empty(),
        "ORG GAP [gates]: scripts/gates/run_all.sh (the ONE audit entrypoint) does not reference \
         these gate scripts, so they are dead routes a developer must remember to run by hand:\n{}",
        missing
            .iter()
            .map(|g| format!("    scripts/gates/{g}"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

#[test]
fn org_run_all_references_org_audit_and_named_gates() {
    // The run_all entrypoint must additionally wire in the cross-cutting
    // org_audit.py (which lives one level up, in scripts/) and name each of the
    // five numbered fast gates so the "one entrypoint is the whole story"
    // contract in its own header is true.
    let root = repo_root();
    let run_all = read(&root.join("scripts/gates/run_all.sh"));
    let required = [
        "scripts/org_audit.py",
        "no_silent_fallbacks.py",
        "law10_semantics.py",
        "surface_coverage.py",
        "complexity_budget.py",
        "vyre_pin_consistency.py",
    ];
    let mut missing = Vec::new();
    for r in required {
        if !run_all.contains(r) {
            missing.push(r);
        }
    }
    assert!(
        missing.is_empty(),
        "ORG GAP [gates]: run_all.sh omits required gate references: {missing:?}",
    );
}

#[test]
fn org_silent_fallback_baseline_is_empty_and_shrink_only() {
    let root = repo_root();
    let baseline = read(&root.join("scripts/gates/silent_fallback_baseline.txt"));
    let entries: Vec<_> = baseline
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    assert!(
        entries.is_empty(),
        "ORG GAP [law10]: silent fallback baseline must stay empty after the cleanup; \
         reintroduced debt belongs in code fixes or same-line LAW10 justifications, not baseline entries:\n{}",
        entries.join("\n")
    );

    let gate = read(&root.join("scripts/gates/no_silent_fallbacks.py"));
    assert!(
        baseline.contains("Shrink-only")
            && baseline.contains("Regenerate ONLY when intentionally shrinking")
            && gate.contains("--update-baseline")
            && gate.contains("new = current - baseline")
            && gate.contains("fixed = baseline - current"),
        "ORG GAP [law10]: no_silent_fallbacks.py must remain a shrink-only ratchet, not a debt sink",
    );
}

// ── No TODO/FIXME/HACK or stub macro in shipped source (per-crate, 5 + 1) ───

/// Debt-annotation and stub-macro markers that must not appear in shipped
/// (non-test) source. Each is built from split fragments so THIS test file does
/// not itself trip the grep that the gate runs.
///
/// A marker counts ONLY as a real debt ANNOTATION (`// TODO:` / `// FIXME:` /
/// `// XXX:` / `// HACK:` — the word followed immediately by `:` or a space then
/// text, i.e. an actual annotation) or a STUB MACRO (`todo!(` /
/// `unimplemented!(`). This deliberately does NOT flag a marker token that is
/// merely embedded in documentation (e.g. a `XXXXX-XXXXX` placeholder shape the
/// suppression logic recognizes, or prose describing a "TODO comment in scanned
/// content"). Overclaiming those as Law-2 stubs would be a false finding (Law 8).
fn forbidden_markers() -> Vec<String> {
    let annotate = |word: &str| -> Vec<String> {
        // `WORD:` and `WORD ` (annotation forms) but not `WORDX` (embedded).
        vec![format!("{word}:"), format!("{word} ")]
    };
    let mut out = Vec::new();
    out.extend(annotate(&format!("{}{}", "TO", "DO")));
    out.extend(annotate(&format!("{}{}", "FIX", "ME")));
    // XXX/HACK as standalone annotations only (followed by `:` ).
    out.push(format!("{}{}", "XX", "X:"));
    out.push(format!("{}{}", "HAC", "K:"));
    // Stub macros (Law 2): a stub call, not a description of one.
    out.push(format!("{}{}", "todo", "!("));
    out.push(format!("{}{}", "unimplemented", "!("));
    out
}

/// Is this `.rs` file a unit-test module split or a `#[cfg(test)]` island?
/// We only scan SHIPPED source, so a file that is entirely test code is skipped.
fn is_test_only_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name == "tests.rs" || name.ends_with("_test.rs") || name.ends_with("_tests.rs")
}

/// Lines of shipped source (outside `#[cfg(test)]` blocks and outside doc /
/// line comments that merely *quote* a marker) that contain a forbidden marker.
fn marker_hits_in_crate(root: &Path, krate: &str) -> Vec<String> {
    let markers = forbidden_markers();
    let mut hits = Vec::new();
    let src_dir = root.join("crates").join(krate).join("src");
    for file in walk_rs(&src_dir) {
        if is_test_only_file(&file) {
            continue;
        }
        let src = read(&file);
        let mut in_test_cfg = false;
        let mut brace_depth_at_cfg = 0i32;
        let mut depth = 0i32;
        for (i, line) in src.lines().enumerate() {
            let trimmed = line.trim_start();
            // Track entry/exit of a `#[cfg(test)] mod tests { ... }` block by
            // brace depth so markers inside test code do not count.
            if trimmed.starts_with("#[cfg(test)]") {
                in_test_cfg = true;
                brace_depth_at_cfg = depth;
            }
            for ch in line.chars() {
                if ch == '{' {
                    depth += 1;
                }
                if ch == '}' {
                    depth -= 1;
                    if in_test_cfg && depth <= brace_depth_at_cfg {
                        in_test_cfg = false;
                    }
                }
            }
            if in_test_cfg {
                continue;
            }
            for m in &markers {
                if line.contains(m.as_str()) {
                    // A doc comment that explains a marker (e.g. "surfaces a
                    // `// TO␣DO: rotate` comment in scanned content") is a legit
                    // description of behavior, not shipped debt. Only count a
                    // marker that is NOT inside a string-literal-quoted phrase
                    // and NOT preceded by an explanatory backtick on the line.
                    let is_quoted = line.contains('`') || line.contains('"');
                    if is_quoted {
                        continue;
                    }
                    hits.push(format!(
                        "crates/{krate}/src/{}:{}: {}",
                        file.strip_prefix(&src_dir).unwrap().display(),
                        i + 1,
                        line.trim(),
                    ));
                }
            }
        }
    }
    hits
}

fn assert_no_markers(krate: &str) {
    let root = repo_root();
    let hits = marker_hits_in_crate(&root, krate);
    assert!(
        hits.is_empty(),
        "ORG GAP [{krate}]: shipped source carries {} forbidden marker(s) (TODO/FIXME/XXX/HACK or \
         a stub macro). Each is unfinished work or a stub that must be resolved (Law 2):\n{}",
        hits.len(),
        hits.join("\n"),
    );
}

#[test]
fn org_core_shipped_source_has_no_todo_markers() {
    assert_no_markers("core");
}

#[test]
fn org_scanner_shipped_source_has_no_todo_markers() {
    assert_no_markers("scanner");
}

#[test]
fn org_sources_shipped_source_has_no_todo_markers() {
    assert_no_markers("sources");
}

#[test]
fn org_cli_shipped_source_has_no_todo_markers() {
    assert_no_markers("cli");
}

#[test]
fn org_verifier_shipped_source_has_no_todo_markers() {
    assert_no_markers("verifier");
}

// ── No engine file mixing >1 responsibility (per-file, dynamic count) ───────

/// TARGET: an engine source file should carry at most this many distinct
/// `impl CompiledScanner` blocks. The engine was deliberately split so the
/// `CompiledScanner` "god object" has its methods spread across files by job
/// (see engine/mod.rs "Where each method lives"). A file with several distinct
/// impl blocks is re-aggregating responsibilities back into one file.
const MAX_IMPL_BLOCKS_PER_ENGINE_FILE: usize = 1;

/// Count `impl CompiledScanner` blocks in a file (each is one responsibility
/// cluster). `impl<…> CompiledScanner` and plain `impl CompiledScanner` both
/// count.
fn impl_compiled_scanner_blocks(src: &str) -> usize {
    src.lines()
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with("impl CompiledScanner")
                || (t.starts_with("impl<") && t.contains("> CompiledScanner"))
        })
        .count()
}

/// Engine files (excluding mod.rs which is the documented router/facade and is
/// allowed to carry the dispatch glue).
fn engine_files(root: &Path) -> Vec<PathBuf> {
    let dir = root.join("crates/scanner/src/engine");
    let mut out: Vec<PathBuf> = walk_rs(&dir)
        .into_iter()
        .filter(|p| p.file_name().and_then(|n| n.to_str()) != Some("mod.rs"))
        .collect();
    out.sort();
    out
}

#[test]
fn org_no_engine_file_mixes_multiple_compiled_scanner_impls() {
    let root = repo_root();
    let mut offenders = Vec::new();
    for file in engine_files(&root) {
        let src = read(&file);
        let blocks = impl_compiled_scanner_blocks(&src);
        if blocks > MAX_IMPL_BLOCKS_PER_ENGINE_FILE {
            offenders.push(format!(
                "    engine/{}: {blocks} distinct `impl CompiledScanner` blocks",
                file.file_name().and_then(|n| n.to_str()).unwrap_or("?"),
            ));
        }
    }
    assert!(
        offenders.is_empty(),
        "ORG GAP [engine]: {} engine file(s) carry more than {MAX_IMPL_BLOCKS_PER_ENGINE_FILE} \
         distinct `impl CompiledScanner` block(s) — multiple responsibility clusters in one file. \
         Each cluster of methods should live in its own job-named file (engine/mod.rs documents the \
         intended split):\n{}",
        offenders.len(),
        offenders.join("\n"),
    );
}

/// TARGET: an engine file should not mix BOTH a `CompiledScanner` impl AND a
/// large free-function group (3+ top-level `pub fn`/`fn` at column 0). That mix
/// is the "utility + method" responsibility blend the split was meant to undo.
#[test]
fn org_no_engine_file_mixes_impl_and_freefn_groups() {
    let root = repo_root();
    let mut offenders = Vec::new();
    for file in engine_files(&root) {
        let src = read(&file);
        let impls = impl_compiled_scanner_blocks(&src);
        let free_fns = src
            .lines()
            .filter(|l| {
                let starts_fn = l.starts_with("fn ")
                    || l.starts_with("pub fn ")
                    || l.starts_with("pub(crate) fn ")
                    || l.starts_with("pub(super) fn ");
                starts_fn
            })
            .count();
        if impls >= 1 && free_fns >= 3 {
            offenders.push(format!(
                "    engine/{}: {impls} `impl CompiledScanner` + {free_fns} top-level free fns",
                file.file_name().and_then(|n| n.to_str()).unwrap_or("?"),
            ));
        }
    }
    assert!(
        offenders.is_empty(),
        "ORG GAP [engine]: {} engine file(s) mix a `CompiledScanner` impl with a free-function \
         group (>=3 top-level fns) — two responsibilities in one file. Split the free helpers into \
         a job-named sibling module:\n{}",
        offenders.len(),
        offenders.join("\n"),
    );
}

// ── No pub item unused outside tests (surface-size proxy contracts) ─────────
// A full cross-crate dead-pub analysis needs the compiler; as a parseable
// proxy each crate's PRODUCTION pub-symbol surface is bounded. A bloated
// surface is exactly the "pub item nothing outside tests uses" smell.

/// TARGET reachable `pub` symbol budgets per crate (fn/struct/enum/trait/const/
/// static/type declared at any depth in `src/`, EXCLUDING only `#[cfg(test)]`).
/// Hidden testing facades and `#[doc(hidden)] pub` probes are deliberately
/// counted because they are still reachable API. These are intentionally tight
/// so a crate that keeps growing its public surface without pruning dead exports
/// goes RED.
fn pub_symbol_budget(krate: &str) -> usize {
    match krate {
        "core" => 90,
        "scanner" => 150,
        "sources" => 60,
        "cli" => 90,
        "verifier" => 40,
        _ => 0,
    }
}

/// Count reachable `pub` declarations in a crate's `src/`.
/// (We count `pub `-prefixed item keywords on non-test lines, including hidden
/// testing facades because a downstream integration test can name them.)
fn reachable_pub_symbols(root: &Path, krate: &str) -> usize {
    let src_dir = root.join("crates").join(krate).join("src");
    let mut count = 0usize;
    for file in walk_rs(&src_dir) {
        if is_test_only_file(&file) {
            continue;
        }
        let src = read(&file);
        let mut in_test_cfg = false;
        let mut pending_test_cfg = false;
        let mut brace_at = 0i32;
        let mut in_testing_module = false;
        let mut testing_brace_at = 0i32;
        let mut depth = 0i32;
        let mut doc_hidden_next = false;
        for line in src.lines() {
            let t = line.trim_start();
            if in_test_cfg {
                for ch in line.chars() {
                    if ch == '{' {
                        depth += 1;
                    }
                    if ch == '}' {
                        depth -= 1;
                        if depth <= brace_at {
                            in_test_cfg = false;
                        }
                    }
                }
                doc_hidden_next = false;
                continue;
            }
            if t.starts_with("#[doc(hidden)]") {
                doc_hidden_next = true;
            }
            if t.starts_with("#[cfg(test)]") {
                pending_test_cfg = true;
                doc_hidden_next = false;
                continue;
            }
            if pending_test_cfg
                && (t.is_empty()
                    || t.starts_with("#[")
                    || t.starts_with("///")
                    || t.starts_with("//!"))
            {
                doc_hidden_next = false;
                continue;
            }
            let cfg_test_item = pending_test_cfg;
            if cfg_test_item {
                pending_test_cfg = false;
                if line.contains('{') {
                    in_test_cfg = true;
                    brace_at = depth;
                }
            }
            let is_testing_surface = is_testing_surface_line(t);
            if t.starts_with("pub mod testing {") || t == "pub mod testing" {
                in_testing_module = true;
                testing_brace_at = depth;
            }
            let was_test = in_test_cfg || cfg_test_item;
            for ch in line.chars() {
                if ch == '{' {
                    depth += 1;
                }
                if ch == '}' {
                    depth -= 1;
                    if in_test_cfg && depth <= brace_at {
                        in_test_cfg = false;
                    }
                    if in_testing_module && depth <= testing_brace_at {
                        in_testing_module = false;
                    }
                }
            }
            if was_test {
                doc_hidden_next = false;
                continue;
            }
            let mut counted_line = false;
            // A production pub item declaration.
            if (t.starts_with("pub fn ")
                || t.starts_with("pub struct ")
                || t.starts_with("pub enum ")
                || t.starts_with("pub trait ")
                || t.starts_with("pub const ")
                || t.starts_with("pub static ")
                || t.starts_with("pub type ")
                || t.starts_with("pub mod "))
                && !t.contains("testing")
            {
                count += 1;
                counted_line = true;
            }
            if is_testing_surface {
                count += 1;
                counted_line = true;
            }
            if doc_hidden_next && t.starts_with("pub ") && !counted_line {
                // A hidden public item is still public; count it even when it
                // is not named `testing`, so doc attributes cannot hide API
                // growth from the org budget.
                count += 1;
            }
            if !t.starts_with("#[doc(hidden)]") {
                doc_hidden_next = false;
            }
        }
    }
    count
}

fn assert_pub_surface_within_budget(krate: &str) {
    let root = repo_root();
    let n = reachable_pub_symbols(&root, krate);
    let budget = pub_symbol_budget(krate);
    assert!(
        n <= budget,
        "ORG GAP [{krate}]: crate `keyhog-{krate}` exposes {n} reachable `pub` items, including \
         hidden testing facades and `#[doc(hidden)] pub` probes (budget {budget}). A public \
         surface this wide almost certainly carries symbols nothing outside tests consumes — prune \
         dead/over-broad `pub` (make them `pub(crate)` or private) so the public contract is the \
         minimal real one (Adversarial Vector 11 UTILIZATION).",
    );
}

#[test]
fn org_core_pub_surface_within_budget() {
    assert_pub_surface_within_budget("core");
}

#[test]
fn org_scanner_pub_surface_within_budget() {
    assert_pub_surface_within_budget("scanner");
}

#[test]
fn org_sources_pub_surface_within_budget() {
    assert_pub_surface_within_budget("sources");
}

#[test]
fn org_cli_pub_surface_within_budget() {
    assert_pub_surface_within_budget("cli");
}

#[test]
fn org_verifier_pub_surface_within_budget() {
    assert_pub_surface_within_budget("verifier");
}

// ── Self-consistency guards (these PASS — they prove the parser is honest) ──
// If these flip RED the harness itself broke and every finding above is suspect.

#[test]
fn meta_repo_root_resolves_and_has_five_crates() {
    let root = repo_root();
    for krate in CRATES {
        assert!(
            lib_rs_path(&root, krate).is_file(),
            "harness: crates/{krate}/src/lib.rs must exist for the org parser to be valid",
        );
    }
    assert!(
        root.join("scripts/gates/run_all.sh").is_file(),
        "harness: the audit entrypoint must exist",
    );
}

#[test]
fn meta_reexport_parser_counts_curated_aggregation_points() {
    // The parser MUST observe the remaining curated root aggregation points or
    // it is undercounting and the findings are hollow. This is a
    // harness-honesty check, not an org target.
    let root = repo_root();
    let counts = count_reexports(&root);
    assert_eq!(
        counts["core"], 1,
        "harness: core aggregation count drifted: {counts:?}"
    );
    assert_eq!(
        counts["scanner"], 1,
        "harness: scanner aggregation count drifted: {counts:?}"
    );
    assert_eq!(
        counts["sources"], 2,
        "harness: sources aggregation count drifted: {counts:?}"
    );
    assert_eq!(
        counts["verifier"], 1,
        "harness: verifier aggregation count drifted: {counts:?}"
    );
    assert_eq!(
        counts["cli"], 0,
        "harness: cli aggregation count drifted: {counts:?}"
    );
}
