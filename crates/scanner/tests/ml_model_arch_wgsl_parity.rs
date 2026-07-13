//! Anti-drift guard binding the GPU WGSL shader's architecture constants to the
//! single Rust owner `ml_scorer::model_arch`.
//!
//! The MoE dimensions (INPUT_DIM=43 after DET-1, EXPERT_COUNT=6, hidden 32/16, the flat
//! `weights.bin` offsets, and the per-expert parameter counts) live ONCE in
//! `model_arch.rs`. The WGSL is now GENERATED from that owner by
//! `gpu::gpu_shader::moe_shader` (a shader source cannot import Rust consts, so
//! the header is `format!`-interpolated from the same constants and the body
//! uses only named WGSL consts). This test validates the GENERATED shader, it
//! extracts every emitted `const` and asserts equality against the Rust owner,
//! plus that the body sizes its arrays / clamps its sigmoid from those named
//! consts. A regression that re-hardcodes a diverging literal, drops the
//! generation, or renumbers `model_arch` without the shader tracking it fails
//! here naming the exact constant.
//!
//! Gated on `feature = "gpu"`: with the feature off the `gpu_shader` module is
//! not compiled at all (there is no shader to check), so `moe_shader_for_test`
//! only exists (and this parity claim only applies (in `gpu` builds)).
#![cfg(feature = "gpu")]

use std::collections::HashMap;

use keyhog_scanner::testing::{ml_model_arch_for_test, moe_shader_for_test, MlModelArch};

fn shader_src() -> String {
    // The GENERATED shader (not the source file): its header carries the real
    // `const NAME: u32 = <value>u;` literals interpolated from model_arch, which
    // is exactly what this parity check pins.
    moe_shader_for_test()
}

/// Parse every `const NAME: u32 = <digits>u;` line into `{NAME: value}`. Trailing
/// `// ...` comments and the `u` suffix are ignored; non-`u32` consts and struct
/// fields (`batch_size: u32,`: no `const`) are skipped.
fn wgsl_u32_consts(src: &str) -> HashMap<String, u64> {
    let mut map = HashMap::new();
    for line in src.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("const ") else {
            continue;
        };
        let Some((name, after)) = rest.split_once(':') else {
            continue;
        };
        let Some((ty, val)) = after.split_once('=') else {
            continue;
        };
        if ty.trim() != "u32" {
            continue;
        }
        let digits: String = val
            .trim()
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if digits.is_empty() {
            continue;
        }
        let value = digits.parse::<u64>().expect("u32 literal parses");
        assert!(
            map.insert(name.trim().to_string(), value).is_none(),
            "duplicate WGSL const {}",
            name.trim()
        );
    }
    map
}

/// Every WGSL `const` (by name) mapped to its expected value derived from the
/// single Rust owner. The set is exhaustive: `wgsl_literals_match_rust_owner`
/// also asserts the shader declares EXACTLY these and no unchecked extras.
fn expected(a: &MlModelArch) -> Vec<(&'static str, u64)> {
    vec![
        ("INPUT_DIM", a.input_dim as u64),
        ("EXPERT_COUNT", a.expert_count as u64),
        ("HIDDEN1", a.expert_fc1_out as u64),
        ("HIDDEN2", a.expert_fc2_out as u64),
        ("GATE_W_OFF", a.gate_w_off as u64),
        ("GATE_W_COUNT", a.gate_w_count as u64),
        ("GATE_B_OFF", a.gate_b_off as u64),
        ("GATE_B_COUNT", a.gate_b_count as u64),
        ("EXPERTS_OFF", a.experts_off as u64),
        ("E_FC1_W", a.expert_fc1_w_count as u64),
        ("E_FC1_B", a.expert_fc1_b_count as u64),
        ("E_FC2_W", a.expert_fc2_w_count as u64),
        ("E_FC2_B", a.expert_fc2_b_count as u64),
        ("E_FC3_W", a.expert_fc3_w_count as u64),
        ("E_FC3_B", a.expert_fc3_b_count as u64),
        ("EXPERT_PARAMS", a.expert_param_count as u64),
        ("WORKGROUP_SIZE", a.workgroup_size as u64),
    ]
}

#[test]
fn wgsl_literals_match_rust_owner() {
    let arch = ml_model_arch_for_test();
    let consts = wgsl_u32_consts(&shader_src());
    let want = expected(&arch);

    for (name, value) in &want {
        let got = consts
            .get(*name)
            .unwrap_or_else(|| panic!("WGSL shader is missing const {name}"));
        assert_eq!(
            *got, *value,
            "WGSL const {name} = {got}u but Rust model_arch derives {value}; the GPU shader \
             diverged from the single owner, update src/gpu/gpu_shader.rs to match model_arch.rs"
        );
    }

    // Adversarial: no WGSL architecture const may exist without a checked
    // counterpart, or a new dimension could drift unguarded.
    let extras: Vec<&str> = consts
        .keys()
        .map(|k| k.as_str())
        .filter(|k| !want.iter().any(|(n, _)| n == k))
        .collect();
    assert_eq!(
        consts.len(),
        want.len(),
        "WGSL declares {} u32 consts but {} are pinned; every architecture const must be \
         checked against model_arch. Unchecked: {extras:?}",
        consts.len(),
        want.len(),
    );
}

#[test]
fn wgsl_body_sizes_arrays_and_clamps_from_named_consts() {
    // The generated body must size its arrays and clamp its sigmoid from the
    // NAMED header consts (never re-inlined literals), so the layout has exactly
    // one definitional home. Each named const's numeric value is separately
    // pinned to the owner by `wgsl_literals_match_rust_owner` and `SIGMOID_SAT`.
    let src = shader_src();

    for (named, label) in [
        ("array<f32, HIDDEN1>", "h1 hidden-1"),
        ("array<f32, HIDDEN2>", "h2 hidden-2"),
        ("array<f32, EXPERT_COUNT>", "gate logits/probs"),
    ] {
        assert!(
            src.contains(named),
            "generated WGSL must size the {label} array as `{named}` (named const, not a literal)"
        );
    }

    // Sigmoid clamp must reference the named SIGMOID_SAT const (whose value the
    // header ties to model_arch::SIGMOID_SATURATION), matching the CPU
    // `ml_scorer::sigmoid` clamp (DET-11 parity reference).
    assert!(
        src.contains("score_logit <= -SIGMOID_SAT"),
        "generated WGSL lower sigmoid clamp must be `-SIGMOID_SAT` (named const)"
    );
    assert!(
        src.contains("score_logit >= SIGMOID_SAT"),
        "generated WGSL upper sigmoid clamp must be `SIGMOID_SAT` (named const)"
    );

    // And the header must declare SIGMOID_SAT at the owner's saturation value.
    let arch = ml_model_arch_for_test();
    let sat = arch.sigmoid_saturation;
    assert!(
        src.contains(&format!("const SIGMOID_SAT: f32 = {sat:.1}")),
        "generated WGSL must declare `const SIGMOID_SAT: f32 = {sat:.1}` from model_arch"
    );
}

#[test]
fn wgsl_buffer_layout_arithmetic_is_internally_consistent() {
    // The parity claim: the shader's own offset arithmetic reconstructs the same
    // flat `weights.bin` layout the Rust forward pass indexes. Proven from the
    // WGSL literals alone (independent of the Rust side), then cross-checked
    // against the owner in `wgsl_literals_match_rust_owner`.
    let c = wgsl_u32_consts(&shader_src());
    let g = |k: &str| *c.get(k).unwrap_or_else(|| panic!("missing WGSL const {k}"));

    assert_eq!(g("GATE_W_COUNT"), g("INPUT_DIM") * g("EXPERT_COUNT"));
    assert_eq!(g("GATE_B_COUNT"), g("EXPERT_COUNT"));
    assert_eq!(g("GATE_B_OFF"), g("GATE_W_OFF") + g("GATE_W_COUNT"));
    assert_eq!(g("EXPERTS_OFF"), g("GATE_B_OFF") + g("GATE_B_COUNT"));
    assert_eq!(g("E_FC1_W"), g("INPUT_DIM") * g("HIDDEN1"));
    assert_eq!(g("E_FC1_B"), g("HIDDEN1"));
    assert_eq!(g("E_FC2_W"), g("HIDDEN1") * g("HIDDEN2"));
    assert_eq!(g("E_FC2_B"), g("HIDDEN2"));
    assert_eq!(g("E_FC3_W"), g("HIDDEN2"));
    assert_eq!(g("E_FC3_B"), 1);
    assert_eq!(
        g("EXPERT_PARAMS"),
        g("E_FC1_W") + g("E_FC1_B") + g("E_FC2_W") + g("E_FC2_B") + g("E_FC3_W") + g("E_FC3_B")
    );
}

#[test]
fn cpu_forward_pass_consumes_owner_input_width() {
    // Ties the LIVE forward pass to the owner: the feature vector the CPU MoE
    // actually scores is exactly INPUT_DIM wide, the same width the WGSL
    // `get_input`/gate loops stride over (`inputs[batch*INPUT_DIM + feat]`).
    let arch = ml_model_arch_for_test();
    let features = keyhog_scanner::ml_scorer::compute_features_with_config(
        "AKIAIOSFODNN7EXAMPLE",
        "aws_key =",
        &[],
        &[],
        &[],
        &[],
    );
    assert_eq!(
        features.len(),
        arch.input_dim,
        "CPU feature vector width must equal model_arch::INPUT_DIM (the WGSL INPUT_DIM stride)"
    );

    let wgsl_input_dim = wgsl_u32_consts(&shader_src())["INPUT_DIM"];
    assert_eq!(
        features.len() as u64,
        wgsl_input_dim,
        "CPU forward-pass input width and WGSL INPUT_DIM must be identical"
    );
}
