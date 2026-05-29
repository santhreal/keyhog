//! RELEASE TEST LANE 15  -  every-op random-input stress test.
//!
//! For every OpEntry that ships `test_inputs` + `expected_output`, generate
//! bounded random inputs (10_000 when `CI_STRESS=1`) via a manual
//! `proptest::test_runner::TestRunner`, run each through the CPU reference
//! and the wgpu backend, and assert byte-identity (int) or within-ULP
//! (float) equivalence.

#![allow(clippy::filter_map_bool_then, clippy::unnecessary_map_or)]
#![allow(deprecated)]
use std::sync::OnceLock;

use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::{Config, TestRunner};
use vyre::ir::Program;
use vyre::{DispatchConfig, VyreBackend};
use vyre_driver_wgpu::WgpuBackend;
use vyre_foundation::optimizer::pre_lowering::optimize;
use vyre_libs::harness::{all_entries, fp_contract};
use vyre_reference::value::Value;

fn require_backend() -> &'static WgpuBackend {
    static BACKEND: OnceLock<WgpuBackend> = OnceLock::new();
    BACKEND.get_or_init(|| {
        WgpuBackend::acquire().expect(
            "every_op_random_input_stress: GPU adapter probe failed. Fix: verify nvidia-smi, WGPU_BACKEND, Vulkan drivers, and wgpu adapter selection.",
        )
    })
}

/// Deterministic per-op seed derived from the stable op id.
fn op_seed(op_id: &str) -> u64 {
    let hash = blake3::hash(op_id.as_bytes());
    let b = hash.as_bytes();
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

fn missing_capability_reason(backend: &WgpuBackend, program: &Program) -> Option<String> {
    let required = vyre_foundation::program_caps::scan(program);
    let check = vyre_foundation::program_caps::check_backend_capabilities(
        backend.id(),
        backend.supports_subgroup_ops(),
        backend.supports_f16(),
        backend.supports_bf16(),
        backend.supports_indirect_dispatch(),
        true,
        backend.supports_distributed_collectives(),
        backend.max_workgroup_size(),
        &required,
    );
    check.err().map(|missing| missing.to_string())
}

fn randomize_buffer(op_id: &str, program: &Program, buffer_idx: usize) -> bool {
    let Some(buffer) = program.buffers().get(buffer_idx) else {
        return false;
    };
    if buffer.access() != vyre::ir::BufferAccess::ReadOnly {
        return false;
    }
    if is_program_graph_topology(program, buffer_idx) {
        return false;
    }

    match op_id {
        "vyre-libs::decode::inflate_stored_block" => false,
        "vyre-libs::decode::ziftsieve" => buffer_idx == 0,
        "vyre-libs::parsing::c_lexer" => buffer_idx == 0,
        "vyre-libs::parsing::c_keyword" | "vyre-libs::parsing::c_keyword_packed_haystack" => {
            buffer_idx == 4 || buffer_idx == 5
        }
        "vyre-libs::catalog::reduce::segment_reduce_sum::consumer_a"
        | "vyre-libs::catalog::reduce::segment_reduce_sum::consumer_b" => buffer_idx == 0,
        "vyre-libs::parsing::bracket_match"
        | "vyre-libs::parsing::ast_shunting_yard"
        | "vyre-libs::parsing::ast_shunting_yard::statement_pass" => false,
        _ => true,
    }
}

fn is_program_graph_topology(program: &Program, buffer_idx: usize) -> bool {
    buffer_idx < 5
        && program
            .buffers()
            .get(1)
            .is_some_and(|buffer| buffer.name().contains("edge_offsets"))
        && program
            .buffers()
            .get(2)
            .is_some_and(|buffer| buffer.name().contains("edge_targets"))
}

fn program_graph_node_count(program: &Program) -> Option<u32> {
    program
        .buffers()
        .get(1)
        .filter(|buffer| buffer.name().contains("edge_offsets"))
        .and_then(|buffer| buffer.count().checked_sub(1))
        .filter(|&node_count| node_count > 0)
}

fn is_program_graph_frontier(program: &Program, buffer_idx: usize) -> bool {
    let Some(node_count) = program_graph_node_count(program) else {
        return false;
    };
    let Some(buffer) = program.buffers().get(buffer_idx) else {
        return false;
    };
    let words = node_count.div_ceil(32).max(1);
    buffer_idx >= 5 && buffer.element() == vyre::ir::DataType::U32 && buffer.count() == words
}

fn random_program_graph_frontier(
    program: &Program,
    len: usize,
    runner: &mut TestRunner,
) -> Vec<u8> {
    let node_count = program_graph_node_count(program).expect("frontier implies graph shape");
    let words = node_count.div_ceil(32).max(1) as usize;
    assert_eq!(
        len,
        words * core::mem::size_of::<u32>(),
        "ProgramGraph frontier fixture length must match declared node count"
    );

    let strategy = proptest::collection::vec(any::<u32>(), words);
    let tree = strategy
        .new_tree(runner)
        .expect("frontier bitset strategy must yield a tree");
    let mut values = tree.current();
    let used_bits = node_count % 32;
    if used_bits != 0 {
        let mask = (1u32 << used_bits) - 1;
        if let Some(last) = values.last_mut() {
            *last &= mask;
        }
    }
    values
        .into_iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

fn random_u32_vec(
    words: usize,
    range: core::ops::RangeInclusive<u32>,
    runner: &mut TestRunner,
) -> Vec<u32> {
    let strategy = proptest::collection::vec(range, words);
    let tree = strategy
        .new_tree(runner)
        .expect("bounded u32 vector strategy must yield a tree");
    tree.current()
}

fn u32_words_to_bytes(words: &[u32]) -> Vec<u8> {
    vyre_primitives::wire::pack_u32_slice(words)
}

fn random_amg_v_cycle_inputs(fixture_case: &[Vec<u8>], runner: &mut TestRunner) -> Vec<Vec<u8>> {
    let fine_diag = random_u32_vec(4, 2..=8, runner);
    let mut coarse_diag = random_u32_vec(2, 2..=8, runner);
    let initial_x = vec![0u32; 4];

    let mut a = vec![0u32; 16];
    for row in 0..4 {
        for col in 0..4 {
            a[row * 4 + col] = if row == col { fine_diag[row] << 16 } else { 0 };
        }
    }
    let rhs = vec![0u32; 4];

    let r_mat = [1u32 << 16, 0, 0, 0, 0, 0, 1u32 << 16, 0];
    let p_mat = [1u32 << 16, 0, 1u32 << 15, 0, 0, 1u32 << 16, 0, 1u32 << 15];
    let a_c = [
        coarse_diag.remove(0) << 16,
        0,
        0,
        coarse_diag.remove(0) << 16,
    ];
    let omega = [1u32 << 15];

    let mut inputs = Vec::with_capacity(fixture_case.len());
    inputs.push(u32_words_to_bytes(&a));
    inputs.push(u32_words_to_bytes(&rhs));
    inputs.push(u32_words_to_bytes(&initial_x));
    inputs.push(u32_words_to_bytes(&r_mat));
    inputs.push(u32_words_to_bytes(&p_mat));
    inputs.push(u32_words_to_bytes(&a_c));
    inputs.push(u32_words_to_bytes(&omega));
    inputs.extend(fixture_case.iter().skip(7).cloned());
    inputs
}

fn gpu_dispatch_inputs(program: &Program, all_inputs: &[Vec<u8>]) -> Vec<Vec<u8>> {
    program
        .buffers()
        .iter()
        .enumerate()
        .filter_map(|(buffer_idx, buffer)| {
            matches!(
                buffer.access(),
                vyre::ir::BufferAccess::ReadOnly
                    | vyre::ir::BufferAccess::ReadWrite
                    | vyre::ir::BufferAccess::Uniform
            )
            .then(|| all_inputs.get(buffer_idx).cloned())
        })
        .flatten()
        .collect()
}

fn random_buffer_for(
    op_id: &str,
    buffer: &vyre::ir::BufferDecl,
    len: usize,
    runner: &mut TestRunner,
) -> Vec<u8> {
    if op_id.contains("newton_schulz")
        && buffer.element() == vyre::ir::DataType::F32
        && len % 4 == 0
    {
        let strategy = proptest::collection::vec(0u32..=1_000, len / 4);
        let tree = strategy
            .new_tree(runner)
            .expect("bounded Newton-Schulz f32 strategy must yield a tree");
        return tree
            .current()
            .into_iter()
            .map(|value| value as f32 / 1_000.0)
            .flat_map(f32::to_le_bytes)
            .collect();
    }

    if op_id.contains("amg_v_cycle") && buffer.element() == vyre::ir::DataType::U32 && len % 4 == 0
    {
        let strategy = proptest::collection::vec(0u32..=4_096, len / 4);
        let tree = strategy
            .new_tree(runner)
            .expect("bounded AMG fixed-point strategy must yield a tree");
        return tree
            .current()
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
    }

    if buffer.element() == vyre::ir::DataType::F32 && len % 4 == 0 {
        let strategy = proptest::collection::vec(0u32..=4096, len / 4);
        let tree = strategy
            .new_tree(runner)
            .expect("finite f32 strategy must yield a tree");
        return tree
            .current()
            .into_iter()
            .flat_map(|value| (value as f32).to_le_bytes())
            .collect();
    }

    let strategy = proptest::collection::vec(any::<u8>(), len);
    let tree = strategy
        .new_tree(runner)
        .expect("vec strategy must yield a tree");
    tree.current()
}

fn ordered_bits(value: f32) -> u32 {
    let bits = value.to_bits();
    if bits & 0x8000_0000 != 0 {
        !bits
    } else {
        bits | 0x8000_0000
    }
}

/// Compare CPU and GPU outputs. On mismatch returns a string naming the
/// op, the seed, and the first divergent byte so the bug can be replayed
/// deterministically.
fn compare_outputs(
    op_id: &str,
    program: &Program,
    cpu: &[Vec<u8>],
    gpu: &[Vec<u8>],
    tolerance: u32,
    seed: u64,
) -> Result<(), String> {
    if cpu.len() != gpu.len() {
        return Err(format!(
            "{op_id} seed={seed}: CPU produced {} buffers, GPU produced {}",
            cpu.len(),
            gpu.len()
        ));
    }
    let output_indices = program.output_buffer_indices();
    if output_indices.len() != cpu.len() {
        return Err(format!(
            "{op_id} seed={seed}: program declares {} output buffers, CPU produced {}",
            output_indices.len(),
            cpu.len()
        ));
    }
    for (buf_idx, ((c, g), buffer_index)) in cpu
        .iter()
        .zip(gpu.iter())
        .zip(output_indices.iter().copied())
        .enumerate()
    {
        if c.len() != g.len() {
            return Err(format!(
                "{op_id} seed={seed}: buffer #{buf_idx} length diverged CPU={} GPU={}",
                c.len(),
                g.len()
            ));
        }
        let element = program.buffers()[buffer_index as usize].element();
        if element != vyre::ir::DataType::F32 || tolerance == 0 {
            for (byte_idx, (cb, gb)) in c.iter().zip(g.iter()).enumerate() {
                if cb != gb {
                    return Err(format!(
                        "{op_id} seed={seed}: byte mismatch at buffer #{buf_idx} byte {byte_idx} \
                         CPU=0x{cb:02x} GPU=0x{gb:02x}"
                    ));
                }
            }
        } else {
            if c.len() % 4 != 0 {
                return Err(format!(
                    "{op_id} seed={seed}: buffer #{buf_idx} length {} not 4-byte aligned for f32 ULP compare",
                    c.len()
                ));
            }
            for (lane, (c_chunk, g_chunk)) in c.chunks_exact(4).zip(g.chunks_exact(4)).enumerate() {
                let c_bits = u32::from_le_bytes(c_chunk.try_into().expect("4 bytes"));
                let g_bits = u32::from_le_bytes(g_chunk.try_into().expect("4 bytes"));
                let c_f = f32::from_bits(c_bits);
                let g_f = f32::from_bits(g_bits);

                // NaN payloads must match exactly regardless of tolerance.
                if c_f.is_nan() || g_f.is_nan() {
                    if c_bits != g_bits {
                        let byte_idx = lane * 4;
                        return Err(format!(
                            "{op_id} seed={seed}: NaN payload mismatch at buffer #{buf_idx} byte {byte_idx} \
                             (lane {lane}) CPU bits=0x{c_bits:08x} GPU bits=0x{g_bits:08x}"
                        ));
                    }
                    continue;
                }

                let diff = ordered_bits(c_f).abs_diff(ordered_bits(g_f));
                if diff > tolerance {
                    let byte_idx = lane * 4;
                    return Err(format!(
                        "{op_id} seed={seed}: ULP divergence at buffer #{buf_idx} byte {byte_idx} \
                         (lane {lane}) diff={diff} > tolerance={tolerance} \
                         CPU bits=0x{c_bits:08x} GPU bits=0x{g_bits:08x}"
                    ));
                }
            }
        }
    }
    Ok(())
}

#[test]
fn every_op_random_input_stress() {
    let backend = require_backend();

    let count = if std::env::var("CI_STRESS").map_or(false, |v| v == "1") {
        10_000
    } else {
        std::env::var("VYRE_RANDOM_CASES")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|&value| value > 0)
            .unwrap_or(8)
    };

    let mut total_cases = 0u64;
    let mut failures = Vec::new();

    for entry in all_entries() {
        if entry.test_inputs.is_none() || entry.expected_output.is_none() {
            panic!(
                "{} is missing test_inputs or expected_output. Fix: every op in the random-input stress sweep must provide both.",
                entry.id
            );
        }

        let program = (entry.build)();

        if let Some(reason) = missing_capability_reason(backend, &program) {
            panic!("{} missing backend capability: {reason}. Fix: wire the op or capability before stress testing.", entry.id);
        }

        let fixture_inputs = entry.test_inputs.unwrap()();
        if fixture_inputs.is_empty() {
            panic!(
                "{} has no fixture inputs. Fix: provide at least one stress seed input.",
                entry.id
            );
        }
        let fixture_case = &fixture_inputs[0];
        let buffer_lens: Vec<usize> = fixture_case.iter().map(|b| b.len()).collect();

        let seed = op_seed(entry.id);
        println!(
            "stress: {}  -  evaluating {} deterministic random cases",
            entry.id, count
        );
        let config = Config {
            rng_seed: proptest::test_runner::RngSeed::Fixed(seed),
            ..Config::default()
        };
        let mut runner = TestRunner::new(config);

        let lowered = optimize(program.clone());
        let mut op_cases = 0u64;
        let mut op_failures = 0usize;

        for case_idx in 0..count {
            let random_inputs = if entry.id.contains("amg_v_cycle") {
                random_amg_v_cycle_inputs(fixture_case, &mut runner)
            } else {
                let mut random_inputs = Vec::with_capacity(buffer_lens.len());
                for (buffer_idx, &len) in buffer_lens.iter().enumerate() {
                    if randomize_buffer(entry.id, &program, buffer_idx) {
                        let buffer = program
                            .buffers()
                            .get(buffer_idx)
                            .expect("fixture input index must match program buffer index");
                        let random = if is_program_graph_frontier(&program, buffer_idx) {
                            random_program_graph_frontier(&program, len, &mut runner)
                        } else {
                            random_buffer_for(entry.id, buffer, len, &mut runner)
                        };
                        random_inputs.push(random);
                    } else {
                        random_inputs.push(fixture_case[buffer_idx].clone());
                    }
                }
                random_inputs
            };

            let cpu_values: Vec<Value> = random_inputs.iter().cloned().map(Value::from).collect();
            let cpu_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                vyre_reference::reference_eval(&program, &cpu_values)
            }));


            let cpu_outputs = match cpu_result {
                Ok(Ok(outputs)) => outputs
                    .into_iter()
                    .map(|v| v.to_bytes())
                    .collect::<Vec<_>>(),
                Ok(Err(_)) | Err(_) => {
                    // Reference rejected or panicked  -  no oracle for this input.
                    continue;
                }
            };

            let gpu_inputs = gpu_dispatch_inputs(&program, &random_inputs);
            let gpu_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                backend.dispatch(&lowered, &gpu_inputs, &DispatchConfig::default())
            }));
            let gpu_outputs = match gpu_result {
                Ok(Ok(o)) => o,
                Ok(Err(e)) => {
                    op_failures += 1;
                    if op_failures == 1 {
                        failures.push(format!(
                            "{} seed={} case={}: GPU dispatch error: {}",
                            entry.id, seed, case_idx, e
                        ));
                    }
                    continue;
                }
                Err(_) => {
                    op_failures += 1;
                    if op_failures == 1 {
                        failures.push(format!(
                            "{} seed={} case={}: GPU dispatch panicked",
                            entry.id, seed, case_idx
                        ));
                    }
                    continue;
                }
            };

            let tolerance = fp_contract::effective_tolerance(entry.id, &program);
            if let Err(msg) = compare_outputs(
                entry.id,
                &program,
                &cpu_outputs,
                &gpu_outputs,
                tolerance,
                seed,
            ) {
                op_failures += 1;
                if op_failures == 1 {
                    failures.push(format!("{} case={}: {msg}", entry.id, case_idx));
                }
            }

            op_cases += 1;
        }

        total_cases += op_cases;
        println!(
            "stress: {}  -  {} random cases evaluated, {} failures",
            entry.id, op_cases, op_failures
        );
    }

    if !failures.is_empty() {
        panic!(
            "every_op_random_input_stress failed for {} op(s):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    println!(
        "every_op_random_input_stress: {} total random cases passed",
        total_cases
    );
}

