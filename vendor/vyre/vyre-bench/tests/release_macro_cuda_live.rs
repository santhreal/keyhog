//! Live CUDA validation for generated compiler-grade release macro workloads.

use vyre::DispatchConfig;
use vyre_bench::cases::release_workloads::{
    build_release_count_macro_case_for_records, release_count_macro_program_specs_for_records,
};
use vyre_driver_cuda::CudaBackend;

const REDUCED_RECORDS: u32 = 512;
const RELEASE_COUNT_CASES: usize = 9;

fn read_u32(bytes: &[u8]) -> u32 {
    let word = bytes
        .get(..4)
        .expect("Fix: release macro count outputs must contain one u32 word.");
    u32::from_le_bytes([word[0], word[1], word[2], word[3]])
}

#[test]
fn reduced_release_count_macro_workloads_match_cpu_oracles_on_live_cuda() {
    let backend = CudaBackend::acquire()
        .expect("Fix: CUDA backend must acquire on the GPU-required release validation host.");
    let specs = release_count_macro_program_specs_for_records(REDUCED_RECORDS);
    assert_eq!(
        specs.len(),
        RELEASE_COUNT_CASES,
        "Fix: live CUDA release macro validation must exercise every count-style compiler-grade workload."
    );

    for spec in specs {
        let case = build_release_count_macro_case_for_records(spec.id, spec.records)
            .expect("Fix: every advertised release count macro spec must build a generated case.");
        assert_eq!(
            case.inputs.len(),
            case.spec.input_buffers,
            "Fix: generated release macro inputs must match the advertised input buffer count for {}.",
            case.spec.id
        );

        let outputs = backend
            .dispatch(&case.program, &case.inputs, &DispatchConfig::default())
            .unwrap_or_else(|err| {
                panic!(
                    "Fix: live CUDA dispatch failed for release macro workload {}: {err}",
                    case.spec.id
                )
            });
        assert_eq!(
            outputs.len(),
            case.expected_outputs.len(),
            "Fix: CUDA output buffer count must match the CPU oracle for {}.",
            case.spec.id
        );
        assert_eq!(
            outputs, case.expected_outputs,
            "Fix: live CUDA release macro workload {} ({}) diverged from CPU oracle: expected count {}, got count {}.",
            case.spec.id,
            case.spec.name,
            read_u32(&case.expected_outputs[0]),
            read_u32(&outputs[0])
        );
    }
}
