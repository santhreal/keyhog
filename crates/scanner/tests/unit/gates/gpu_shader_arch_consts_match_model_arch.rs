//! Gate: the WGSL MoE shader's architecture constants must equal the Rust
//! single-owner values in `ml_scorer/model_arch.rs`.
//!
//! WGSL cannot import Rust consts, so the shader necessarily carries a second
//! textual copy of INPUT_DIM / EXPERT_COUNT / HIDDEN1 / HIDDEN2 and the derived
//! weight-layout offsets. A drift between the two (e.g. a model retrain widening
//! a hidden layer, or DET-1 bumping INPUT_DIM 42→43, updated on the Rust side
//! only) would make the GPU MoE read the weight buffer with the WRONG layout
//! silently wrong scores, not a compile error.
//!
//! The shader is now GENERATED from `model_arch` by
//! [`crate::gpu::gpu_shader::moe_shader`], so drift is structurally impossible.
//! This gate proves that: it parses the constants out of the *generated* WGSL
//! and asserts each equals its `model_arch` owner. If a future edit re-hardcodes
//! a literal that disagrees (or the generation is removed), this fails CI naming
//! the exact mismatched constant.

fn extract_wgsl_const(shader_src: &str, name: &str) -> u32 {
    let needle = format!("const {name}: u32 = ");
    let line = shader_src
        .lines()
        .find(|line| line.trim_start().starts_with(&needle))
        .unwrap_or_else(|| panic!("generated WGSL must declare `{needle}...`"));
    let value = line
        .trim_start()
        .strip_prefix(&needle)
        .and_then(|rest| rest.split('u').next())
        .unwrap_or_else(|| panic!("unparseable WGSL const line: {line}"));
    value
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("non-numeric WGSL const value in: {line}"))
}

#[test]
fn gpu_shader_arch_consts_match_model_arch() {
    let arch = keyhog_scanner::testing::ml_model_arch_for_test();

    let shader = keyhog_scanner::testing::moe_shader_for_test();

    // (WGSL const name in the generated shader, model_arch owner value)
    let pairs: [(&str, usize); 4] = [
        ("INPUT_DIM", arch.input_dim),
        ("EXPERT_COUNT", arch.expert_count),
        ("HIDDEN1", arch.expert_fc1_out),
        ("HIDDEN2", arch.expert_fc2_out),
    ];
    for (wgsl_name, owner) in pairs {
        let wgsl = extract_wgsl_const(&shader, wgsl_name);
        assert_eq!(
            wgsl as usize, owner,
            "generated WGSL `{wgsl_name}` ({wgsl}) diverged from its model_arch owner \
             ({owner}); the GPU MoE would read the weight buffer with the wrong layout. \
             The shader header is generated in gpu_shader::moe_shader, fix the model_arch \
             mapping there, never hardcode a literal."
        );
    }

    // The derived weight-layout offsets/counts must also track the owner.
    let derived: [(&str, usize); 3] = [
        ("GATE_W_COUNT", arch.gate_w_count),
        ("EXPERTS_OFF", arch.experts_off),
        ("EXPERT_PARAMS", arch.expert_param_count),
    ];
    for (wgsl_name, owner) in derived {
        let wgsl = extract_wgsl_const(&shader, wgsl_name);
        assert_eq!(
            wgsl as usize, owner,
            "generated WGSL `{wgsl_name}` ({wgsl}) diverged from model_arch ({owner})"
        );
    }

    // Tripwire against re-hardcoding: the shader BODY (everything after the
    // generated header's last const) must not contain a raw architecture
    // literal. Named WGSL consts only, so the layout can change in exactly one
    // place (model_arch).
    let body = shader
        .split_once("const SIGMOID_SAT")
        .map(|(_, rest)| rest)
        .unwrap_or(&shader);
    for banned in [
        "array<f32, 32>",
        "array<f32, 16>",
        "array<f32, 6>",
        "= 42u",
        "252u",
    ] {
        assert!(
            !body.contains(banned),
            "shader body must not hardcode architecture literal `{banned}`: reference the \
             generated named WGSL const (INPUT_DIM/HIDDEN1/EXPERT_COUNT/…) instead"
        );
    }
}

/// The generated WGSL must PARSE and TYPE-CHECK as valid shader source, no GPU
/// adapter needed. This guards the const-expression forms the generation relies
/// on (`array<f32, HIDDEN1>`, `-SIGMOID_SAT`): a naga-rejected shader would only
/// fail at runtime GPU-init on a real device, invisible to GPU-less CI.
#[test]
fn generated_moe_shader_is_valid_wgsl() {
    let shader = keyhog_scanner::testing::moe_shader_for_test();
    let module = naga::front::wgsl::parse_str(&shader).unwrap_or_else(|e| {
        panic!(
            "generated MoE WGSL failed to parse:\n{}",
            e.emit_to_string(&shader)
        )
    });
    let mut validator = naga::valid::Validator::new(
        naga::valid::ValidationFlags::all(),
        naga::valid::Capabilities::all(),
    );
    validator
        .validate(&module)
        .unwrap_or_else(|e| panic!("generated MoE WGSL failed validation: {e:?}"));
}
