//! xtask dispatcher for the vyre workspace.

use std::env;
use std::process;

mod abstraction_gate;
mod bench_crossback;
mod catalog;
mod check_cat_a;
mod compile;
mod dep_drift;
mod gate1;
mod hash;
mod lego_audit;
mod lint_shape_tests;
mod list_ops;
mod paths;
mod print_composition;
mod quick;
mod quick_cache;
mod release_gate;
mod shrink;
mod trace_f32;

fn print_help() {
    println!(
        "vyre xtask runner\n\
         \n\
         USAGE:\n\
           cargo xtask <subcommand> [options]\n\
         \n\
         SUBCOMMANDS:\n\
           quick-check --op NAME               Run minimal <5s verification path for a single op\n\
           abstraction-gate                     Enforce registered building-block boundaries\n\
           bench-crossback [program]           Cross-backend perf table\n\
           shrink <file.vir> <oracle.sh>       Delta-debug a crashing vyre wire formulation down to a minimal reproducer\n\
           check-cat-a                         Run every Cat-A pre-merge gate\n\
           compile <program.vir> --to TARGET   Emit target artifact(s) (wgsl/spirv/ptx/metal/hlsl)\n\
           dep-drift                           Fail if any repo manifest pins a workspace-managed dependency to a different version\n\
           print-composition <op_id>           Walk an op's Region tree and print its decomposition chain\n\
           trace-f32 <op_id>                   Run an op's test_inputs through vyre-reference and dump expected_output literal\n\
           gate1                               Enforce Gate 1 complexity budget (CI floor)\n\
           list-ops [--write PATH]             Walk registries; print op catalog. Optional: write markdown snapshot\n\
           catalog [--out DIR] [--check]       Emit one markdown table per subsystem under docs/catalog; --check gates drift\n\
           release-gate                        Pre-publish sanity checks (catalog + gate1 + Cargo.lock clean)\n\
           lego-audit                          Deeper LEGO-block enforcement (no-reinvention, depth-of-composition, primitive coverage, chain coverage)\n\
         \n\
           --help                              Print this message\n"
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Fix: missing subcommand. See --help.");
        process::exit(1);
    }

    match args[1].as_str() {
        "quick-check" => quick::cmd_quick_check(&args),
        "abstraction-gate" => abstraction_gate::run(&args),
        "bench-crossback" => bench_crossback::run(&args),
        "shrink" => shrink::run(&args),
        "check-cat-a" => check_cat_a::run(&args),
        "compile" => compile::run(&args),
        "dep-drift" => dep_drift::run(&args),
        "print-composition" => print_composition::run(&args),
        "list-ops" => list_ops::run(&args),
        "catalog" => catalog::run(&args),
        "release-gate" => release_gate::run(&args),
        "trace-f32" => trace_f32::run_cmd(&args),
        "gate1" => gate1::run(&args),
        "lego-audit" => lego_audit::run(&args),
        "lint-shape-tests" => lint_shape_tests::run(&args),
        "--help" | "-h" => {
            print_help();
            process::exit(0);
        }
        _ => {
            eprintln!("Fix: unknown subcommand '{}'. See --help.", args[1]);
            process::exit(1);
        }
    }
}
