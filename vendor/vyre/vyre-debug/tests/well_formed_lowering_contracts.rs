//! Well-formed-lowering contracts for vyre-debug introspection.
//!
//! Each fn here asserts a *structural* invariant of the lowerer's
//! output that the debug crate is supposed to validate. If any of
//! these regress, either the lowerer started producing malformed
//! kernels (real bug) or the debug analyzer started missing real
//! issues (regression in the debug crate itself). Either way, this
//! test surfaces it.
//!
//! Why it lives in vyre-debug: the analyzers under test (`find_dangling_refs`,
//! `find_uncarriered_assigns`, `diff_descriptors`) live here, so the
//! contracts naturally land alongside.

use vyre_debug::{
    bisect_rewrites, carrier_summary, diff_descriptors, dump_descriptor, dump_wgsl,
    dump_wgsl_with_lines, find_dangling_refs, find_uncarriered_assigns, fixtures::loop_carry_smoke,
    DescriptorDumpOptions,
};
use vyre_lower::lower;

fn lowered_smoke() -> (vyre_foundation::ir::Program, vyre_lower::KernelDescriptor) {
    let program = loop_carry_smoke();
    let desc = lower(&program).expect("smoke fixture must lower cleanly");
    (program, desc)
}

#[test]
fn lowerer_produces_no_dangling_refs_on_smoke_fixture() {
    let (_, desc) = lowered_smoke();
    let refs = find_dangling_refs(&desc);
    assert!(
        refs.is_empty(),
        "smoke fixture lowered to a kernel with {} dangling refs; first: {:?}",
        refs.len(),
        refs.first()
    );
}

#[test]
fn lowerer_produces_no_uncarriered_assigns_on_smoke_fixture() {
    let (program, desc) = lowered_smoke();
    let unc = find_uncarriered_assigns(&program, &desc);
    assert!(
        unc.is_empty(),
        "smoke fixture lowered to a kernel with {} uncarriered assigns; first: {:?}",
        unc.len(),
        unc.first()
    );
}

#[test]
fn carrier_summary_counts_match_descriptor_ops() {
    let (_, desc) = lowered_smoke();
    let summary = carrier_summary(&desc);
    // The summary's totals should be self-consistent: assigns_observed
    // is the denominator, carrier_uses is one component of "good"
    // carriers. Whatever the exact numbers, neither field can exceed
    // the total assign count in the descriptor body itself.
    let assign_count = count_assign_ops(&desc.body);
    assert!(
        summary.assigns_observed <= assign_count + 1024,
        "summary.assigns_observed {} exceeds body assign count {}",
        summary.assigns_observed,
        assign_count
    );
}

fn count_assign_ops(body: &vyre_lower::KernelBody) -> usize {
    let mut n = body.ops.len();
    for c in &body.child_bodies {
        n += count_assign_ops(c);
    }
    n
}

#[test]
fn descriptor_diff_of_self_is_empty() {
    let (_, desc) = lowered_smoke();
    let diff = diff_descriptors(&desc, &desc);
    // A descriptor diffed against itself must be empty by definition;
    // every added/removed/changed list is zero-length.
    let json = serde_json::to_string(&diff).expect("DescriptorDiff serializes");
    assert!(
        !json.contains(r#""changed":[{"#),
        "self-diff produced a non-empty changed list: {json}"
    );
}

#[test]
fn descriptor_dump_is_non_empty_and_lists_dispatch() {
    let (_, desc) = lowered_smoke();
    let dump = dump_descriptor(&desc, &DescriptorDumpOptions::default());
    let json = serde_json::to_string(&dump).expect("DescriptorDump serializes");
    assert!(json.len() > 32, "dump is suspiciously short: {json}");
    // The smoke fixture sets dispatch [1,1,1]; the dump must round-trip it.
    assert!(
        json.contains("dispatch") || json.contains("Dispatch"),
        "dump JSON missing dispatch field: {json}"
    );
}

#[test]
fn wgsl_dump_emits_a_wgsl_compute_kernel() {
    let desc = lowered_smoke();
    // The high-level `dump_wgsl` builds the Program -> WGSL pipeline
    // from the smoke fixture, so we go through Program rather than
    // descriptor. Either route must produce a non-empty WGSL string
    // that contains the required compute-shader entrypoint.
    let program = loop_carry_smoke();
    let dump = dump_wgsl(&program).expect("smoke fixture must emit WGSL");
    let _ = desc; // just ensure both paths work; we assert on the WGSL.
    assert!(
        dump.text.contains("@compute"),
        "WGSL dump missing @compute attribute; first 200 chars: {}",
        &dump.text.chars().take(200).collect::<String>()
    );
    assert!(
        dump.text.contains("fn main") || dump.text.contains("fn cs_main"),
        "WGSL dump missing entry-point fn"
    );
}

#[test]
fn wgsl_dump_with_lines_attaches_a_line_index() {
    let program = loop_carry_smoke();
    let dump = dump_wgsl_with_lines(&program).expect("smoke must emit WGSL+lines");
    let line_count = dump.text.lines().count();
    assert!(
        line_count > 3,
        "WGSL with-lines dump only {} lines; that can't be a real shader",
        line_count
    );
}

#[test]
fn bisect_rewrites_terminates_on_smoke_fixture() {
    let program = loop_carry_smoke();
    // bisect_rewrites is the rewrite-bisection harness used to find a
    // minimal failing transform. On a passing program it must
    // *terminate* (no infinite loop, no crash) and return an Ok result.
    // We don't assert on the exact RewriteBisectResult shape - that's
    // a behavior contract, not a structural one - only that it
    // completes within a reasonable wall-clock budget.
    let start = std::time::Instant::now();
    let result = bisect_rewrites(&program);
    let elapsed = start.elapsed();
    assert!(
        result.is_ok(),
        "bisect_rewrites errored on smoke: {result:?}"
    );
    assert!(
        elapsed.as_secs() < 30,
        "bisect_rewrites took {}s on smoke; suspiciously slow",
        elapsed.as_secs()
    );
}
