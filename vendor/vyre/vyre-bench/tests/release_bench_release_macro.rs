//! Contracts for the Criterion entrypoint exercising compiler-grade release workloads.

#[test]
fn release_macro_program_specs_build_real_programs_for_criterion() {
    let specs = vyre_bench::cases::release_workloads::release_macro_program_specs();
    assert!(
        specs.len() >= 10,
        "Fix: Criterion release macro program builder coverage must include every synthetic release family."
    );

    let mut total_records = 0_u64;
    for spec in specs {
        assert!(
            spec.records >= 1_048_576,
            "Fix: release macro spec `{}` must stay at release scale.",
            spec.id
        );
        assert!(
            spec.min_speedup_x >= 100,
            "Fix: release macro spec `{}` must carry the CUDA 100x release contract.",
            spec.id
        );
        let program = vyre_bench::cases::release_workloads::build_release_macro_program(spec.id)
            .unwrap_or_else(|| panic!("Fix: release macro spec `{}` must build.", spec.id));
        let input_buffers = program
            .buffers()
            .iter()
            .filter(|buffer| {
                matches!(
                    buffer.access(),
                    vyre::ir::BufferAccess::ReadOnly | vyre::ir::BufferAccess::Uniform
                )
            })
            .count();
        assert_eq!(
            input_buffers, spec.input_buffers,
            "Fix: release macro spec `{}` input count must match generated Program.",
            spec.id
        );
        assert!(
            program.buffers().iter().any(|buffer| {
                matches!(
                    buffer.access(),
                    vyre::ir::BufferAccess::WriteOnly | vyre::ir::BufferAccess::ReadWrite
                )
            }),
            "Fix: release macro spec `{}` must produce at least one output buffer.",
            spec.id
        );
        total_records += u64::from(spec.records);
    }

    assert!(
        total_records >= 10 * 1_048_576,
        "Fix: Criterion release macro coverage must span at least ten million logical records."
    );
}

#[test]
fn release_criterion_entrypoint_includes_release_macro_build_group() {
    let source = include_str!("../benches/release.rs");
    assert!(
        source.contains("compiler_grade_release_program_build_scale"),
        "Fix: release Criterion entrypoint must include compiler-grade release program builders."
    );
    assert!(
        source.contains("compiler_grade_release/program_build"),
        "Fix: benchmark group must be named as release macro program-build coverage."
    );
    assert!(
        source.contains("build_release_macro_program"),
        "Fix: Criterion must build release macro Programs, not only scan registry metadata."
    );
}
