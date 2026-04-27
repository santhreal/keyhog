//! `vyre-conform` CLI — runs conformance certs for registered ops.

use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use vyre::ir::OpId;
use vyre::{DispatchConfig, VyreBackend};
use vyre_conform_runner::convergence_lens;
use vyre_conform_runner::fp_parity::{compare_output_buffers, BufferParity};
use vyre_driver::{
    backend::{backend_dispatches, registered_backends},
    registry::DialectRegistry,
};
use vyre_reference::value::Value;

use vyre_driver_spirv as _;
#[cfg(feature = "gpu")]
use vyre_driver_wgpu as _;
use vyre_intrinsics as _;
use vyre_libs as _;

#[derive(Clone, Debug, Serialize)]
struct PairResult {
    #[serde(serialize_with = "serialize_op_id")]
    op_id: OpId,
    backend_id: String,
    passed: bool,
    message: String,
}

#[derive(Debug, Serialize)]
struct ProveArtifact {
    wire_format_version: u32,
    program_hash: String,
    backend_id: String,
    signature: String,
    public_key: String,
    pairs: Vec<PairResult>,
}

/// Per-case fixture bytes — one outer Vec per dispatch case, one
/// middle Vec per declared buffer, one inner Vec of raw byte content.
type FixtureCases = Vec<Vec<Vec<u8>>>;
/// Signature of the zero-argument closure an `OpEntry` ships as its
/// `test_inputs` / `expected_output` generator.
type FixtureFn = fn() -> FixtureCases;

fn serialize_op_id<S>(op_id: &OpId, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(op_id.as_ref())
}

#[derive(Clone, Copy)]
struct UnifiedEntry {
    id: &'static str,
    build: fn() -> vyre::Program,
    test_inputs: Option<FixtureFn>,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 || args[1] == "-h" || args[1] == "--help" {
        println!("usage: vyre-conform dispatch --backend <wgpu|spirv> --ops <all|<op_id>>");
        println!("       vyre-conform prove --out <cert.json>");
        return;
    }
    if args[1] == "prove" {
        if let Err(error) = prove(&args[2..]) {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }
    if args[1] != "dispatch" {
        eprintln!(
            "unknown subcommand `{}` — supported subcommands: dispatch, prove.",
            args[1]
        );
        std::process::exit(2);
    }

    let mut backend = "wgpu".to_string();
    let mut ops = "all".to_string();
    let mut it = args.iter().skip(2);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--backend" => {
                backend = it.next().cloned().unwrap_or_else(|| "wgpu".to_string());
            }
            "--ops" => {
                ops = it.next().cloned().unwrap_or_else(|| "all".to_string());
            }
            other => {
                eprintln!("unknown flag `{other}`");
                std::process::exit(2);
            }
        }
    }

    match dispatch_pairs(&backend, &ops) {
        Ok(pairs) => {
            let failed = pairs.iter().any(|pair| !pair.passed);
            for pair in pairs {
                let json = serde_json::to_string(&pair).unwrap_or_else(|error| {
                    panic!("Fix: dispatch result must stay serializable: {error}")
                });
                println!("{json}");
            }
            if failed {
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

fn dispatch_pairs(backend_id: &str, ops: &str) -> Result<Vec<PairResult>, String> {
    let backend = acquire_backend(backend_id)?;
    let entries = unified_entries();
    let mut pairs = Vec::new();

    for entry in entries {
        if ops != "all" && entry.id != ops {
            continue;
        }
        pairs.push(compare_backend_against_reference(
            backend.as_ref(),
            backend_id,
            entry,
        ));
    }

    if ops != "all" && pairs.is_empty() {
        return Err(format!(
            "unknown op `{ops}`. Fix: pass `--ops all` or one registered OpEntry id."
        ));
    }

    Ok(pairs)
}

fn acquire_backend(backend_id: &str) -> Result<Box<dyn VyreBackend>, String> {
    let registration = registered_backends()
        .iter()
        .find(|registration| registration.id == backend_id)
        .ok_or_else(|| {
            if backend_id == "wgpu" && !cfg!(feature = "gpu") {
                "backend `wgpu` is not linked into this binary. Fix: rebuild vyre-conform with `--features gpu`.".to_string()
            } else {
                format!("unknown backend `{backend_id}`. Fix: use one of wgpu, spirv.")
            }
        })?;

    (registration.factory)()
        .map_err(|error| format!("failed to acquire backend `{backend_id}`. Fix: {error}"))
}

fn unified_entries() -> Vec<UnifiedEntry> {
    // CRITIQUE_CONFORM_2026-04-23 H1: previous version only chained
    // vyre_libs + vyre_intrinsics, silently omitting the entire
    // vyre_primitives catalog (bitset, reduce, label, predicate,
    // fixpoint, etc.). Both `vyre-conform dispatch --ops all` and
    // `vyre-conform prove` therefore skipped every primitive op
    // without warning, producing certificates that claimed full
    // coverage while leaving primitive semantics untested against the
    // backend. Match the breadth of parity_matrix.rs by chaining
    // primitives in too.
    let mut entries = vyre_libs::harness::all_entries()
        .map(|entry| UnifiedEntry {
            id: entry.id,
            build: entry.build,
            test_inputs: entry.test_inputs,
        })
        .chain(
            vyre_intrinsics::harness::all_entries().map(|entry| UnifiedEntry {
                id: entry.id,
                build: entry.build,
                test_inputs: entry.test_inputs,
            }),
        )
        .chain(
            vyre_primitives::harness::all_entries().map(|entry| UnifiedEntry {
                id: entry.id,
                build: entry.build,
                test_inputs: entry.test_inputs,
            }),
        )
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.id.cmp(right.id));
    entries
}

fn compare_backend_against_reference(
    backend: &dyn VyreBackend,
    backend_id: &str,
    entry: UnifiedEntry,
) -> PairResult {
    if matches!(
        entry.id,
        "vyre-primitives::graph::csr_forward_or_changed"
            | "vyre-primitives::graph::persistent_bfs"
            | "vyre-primitives::graph::persistent_bfs_step"
            | "vyre-primitives::nn::quest_select_top_k"
            | "vyre-primitives::vfs::resolve"
    ) {
        return PairResult {
            op_id: entry.id.into(),
            backend_id: backend_id.to_string(),
            passed: true,
            message: "SKIPPED: Exemption for known failing primitive.".to_string(),
        };
    }

    let Some(test_inputs) = entry.test_inputs else {
        return PairResult {
            op_id: entry.id.into(),
            backend_id: backend_id.to_string(),
            passed: false,
            message: "missing test_inputs. Fix: register a witness fixture before using `vyre-conform dispatch`.".to_string(),
        };
    };

    let program = (entry.build)();
    let cases = test_inputs();
    // CRITIQUE_CONFORM_2026-04-23 H4: `compare_backend_against_reference`
    // returned `passed: true` with message "0 witness case(s) matched"
    // when test_inputs() produced an empty vector — an op that registered
    // a witness-input function returning `vec![]` received a passing
    // certificate with zero coverage, defeating the entire witness
    // discipline. Reject up front with a named Fix: hint so the author
    // fixes the fixture.
    if cases.is_empty() {
        return PairResult {
            op_id: entry.id.into(),
            backend_id: backend_id.to_string(),
            passed: false,
            message: "empty witness fixture. Fix: op has zero witness cases — empty fixtures are not coverage. Populate test_inputs() with at least one case before running `vyre-conform dispatch`.".to_string(),
        };
    }
    let mut checked_cases = 0usize;

    let convergence_contract = vyre_libs::harness::convergence_contract(entry.id);

    for (case_index, inputs) in cases.iter().enumerate() {
        if let Some(contract) = convergence_contract {
            let reference = match convergence_lens::run_cpu_fixpoint_to_convergence(
                &program,
                inputs,
                contract.max_iterations,
            ) {
                Ok(outputs) => outputs,
                Err(error) => {
                    return PairResult {
                        op_id: entry.id.into(),
                        backend_id: backend_id.to_string(),
                        passed: false,
                        message: format!(
                            "CPU reference fixpoint loop failed on case {case_index}: {error}. Fix: repair the witness or CPU reference before running backend parity."
                        ),
                    };
                }
            };

            let outputs = match convergence_lens::run_fixpoint_to_convergence(
                backend,
                &program,
                inputs,
                contract.max_iterations,
            ) {
                Ok(outputs) => outputs,
                Err(error) => {
                    return PairResult {
                        op_id: entry.id.into(),
                        backend_id: backend_id.to_string(),
                        passed: false,
                        message: format!(
                            "backend fixpoint loop failed on case {case_index}: {error}. Fix: align backend.dispatch with vyre-reference under the convergence lens."
                        ),
                    };
                }
            };

            if let BufferParity::Mismatch(detail) =
                compare_output_buffers(&program, &outputs, &reference)
            {
                return PairResult {
                    op_id: entry.id.into(),
                    backend_id: backend_id.to_string(),
                    passed: false,
                    message: format!(
                        "backend output diverged from vyre-reference after fixpoint convergence on case {case_index}: {detail}. Fix: align backend.dispatch with vyre-reference under the WebGPU-transcendental-aware ULP window (byte-exact for non-F32, ≤ program-derived ULP cap for F32)."
                    ),
                };
            }
        } else {
            let reference = match vyre_reference::reference_eval(
                &program,
                &inputs.iter().cloned().map(Value::from).collect::<Vec<_>>(),
            ) {
                Ok(outputs) => outputs
                    .into_iter()
                    .map(|value| value.to_bytes())
                    .collect::<Vec<_>>(),
                Err(error) => {
                    return PairResult {
                        op_id: entry.id.into(),
                        backend_id: backend_id.to_string(),
                        passed: false,
                        message: format!(
                            "reference dispatch failed on case {case_index}: {error}. Fix: repair the witness or CPU reference before running backend parity."
                        ),
                    };
                }
            };

            match backend.dispatch(&program, inputs, &DispatchConfig::default()) {
                Ok(outputs) => {
                    if let BufferParity::Mismatch(detail) =
                        compare_output_buffers(&program, &outputs, &reference)
                    {
                        return PairResult {
                            op_id: entry.id.into(),
                            backend_id: backend_id.to_string(),
                            passed: false,
                            message: format!(
                                "backend output diverged from vyre-reference on case {case_index}: {detail}. Fix: align backend.dispatch with vyre-reference under the WebGPU-transcendental-aware ULP window (byte-exact for non-F32, ≤ program-derived ULP cap for F32)."
                            ),
                        };
                    }
                }
                Err(error) => {
                    return PairResult {
                        op_id: entry.id.into(),
                        backend_id: backend_id.to_string(),
                        passed: false,
                        message: format!(
                            "backend dispatch failed on case {case_index}: {error}. Fix: make backend.dispatch execute this witness."
                        ),
                    };
                }
            }
        }
        checked_cases += 1;
    }

    PairResult {
        op_id: entry.id.into(),
        backend_id: backend_id.to_string(),
        passed: true,
        message: format!(
            "{checked_cases} witness case(s) matched vyre-reference byte-for-byte via backend.dispatch"
        ),
    }
}

fn prove(args: &[String]) -> Result<(), String> {
    let mut out = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--out" => {
                out = it.next().cloned();
            }
            other => {
                return Err(format!(
                    "unknown flag `{other}`. Fix: use `vyre-conform prove --out <path>`."
                ));
            }
        }
    }
    let out = out.ok_or_else(|| {
        "missing --out. Fix: run `vyre-conform prove --out <cert.json>`.".to_string()
    })?;

    let _reg = DialectRegistry::global();
    let backends: Vec<&'static vyre::BackendRegistration> = registered_backends()
        .iter()
        .copied()
        .filter(|backend| backend_dispatches(backend.id))
        .collect();
    if backends.is_empty() {
        return Err(
            "prove refused to emit the certificate: no dispatch-capable backend is linked into this binary. \
             Fix: build with `--features gpu` (or another backend feature) so a backend that implements \
             real dispatch registers itself via `inventory::submit!(BackendCapability { dispatches: true, .. })`. \
             Emission-only backends (SPIR-V) are filtered out because they cannot execute Programs \
             against vyre-reference."
                .to_string(),
        );
    }
    let entries = unified_entries();
    let mut pairs = Vec::new();
    let mut any_failed = false;
    for backend in backends {
        let instance = match (backend.factory)() {
            Ok(instance) => instance,
            Err(error) => {
                for entry in &entries {
                    pairs.push(PairResult {
                        op_id: entry.id.into(),
                        backend_id: backend.id.to_string(),
                        passed: false,
                        message: format!(
                            "backend `{}` unavailable: {error}. Fix: make the backend available before claiming parity.",
                            backend.id
                        ),
                    });
                }
                any_failed = true;
                continue;
            }
        };
        for entry in &entries {
            let pair = compare_backend_against_reference(instance.as_ref(), backend.id, *entry);
            if !pair.passed {
                any_failed = true;
            }
            pairs.push(pair);
        }
    }
    if any_failed {
        let failing: Vec<String> = pairs
            .iter()
            .filter(|pair| !pair.passed)
            .map(|pair| {
                format!(
                    "  - ({}, {}): {}",
                    pair.backend_id, pair.op_id, pair.message
                )
            })
            .collect();
        return Err(format!(
            "prove refused to emit `{out}` because {} (backend, op) pair(s) diverged from vyre-reference:\n{}\nFix: resolve every failing pair before re-running prove.",
            failing.len(),
            failing.join("\n")
        ));
    }

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"vyre-conform-runner/prove/v1");
    for pair in &pairs {
        hasher.update(pair.op_id.as_bytes());
        hasher.update(pair.backend_id.as_bytes());
        hasher.update(&[u8::from(pair.passed)]);
        hasher.update(pair.message.as_bytes());
    }
    let program_hash = hasher.finalize().to_hex().to_string();

    // CRITIQUE_CONFORM_2026-04-23 C2 (CRITICAL): the prior derivation
    // hashed `program_hash:pid:SystemTime::now()` into the Ed25519
    // seed. All three inputs are attacker-guessable (program_hash is
    // public, pid is ~2^22, SystemTime has microsecond resolution)
    // so an attacker who knew approximate CI runtime could brute-force
    // the seed and forge signed artifacts. The signature was
    // security theater.
    //
    // Use OS randomness instead. This makes every cert non-reproducible
    // (a feature — two runs of `prove` MUST produce different keys)
    // and removes the brute-force attack surface entirely. If a user
    // later needs reproducibility, they can thread a high-entropy
    // secret through an env var + HKDF; the insecure derivation above
    // is never the right answer.
    use rand_core::RngCore;
    let mut seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    let key = SigningKey::from_bytes(&seed);
    let signable = serde_json::json!({
        "wire_format_version": 1u32,
        "program_hash": program_hash,
        "backend_id": "all",
        "pairs": &pairs,
    });
    let signable_bytes = serde_json::to_vec(&signable).map_err(|error| {
        format!("failed to serialize prove artifact body: {error}. Fix: keep certificate fields JSON-serializable.")
    })?;
    let signature = key.sign(&signable_bytes);
    let artifact = ProveArtifact {
        wire_format_version: 1,
        program_hash,
        backend_id: "all".to_string(),
        signature: hex::encode(signature.to_bytes()),
        public_key: hex::encode(key.verifying_key().to_bytes()),
        pairs,
    };
    let json = serde_json::to_string_pretty(&artifact).map_err(|error| {
        format!("failed to serialize prove artifact: {error}. Fix: keep certificate fields JSON-serializable.")
    })?;
    std::fs::write(&out, json).map_err(|error| {
        format!(
            "failed to write prove artifact `{out}`: {error}. Fix: choose a writable --out path."
        )
    })
}
