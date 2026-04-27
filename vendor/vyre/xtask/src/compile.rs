//! `cargo xtask compile` — multi-target emitter harness.
//!
//! P7.4 contract: one IR → backend artifacts + a
//! byte-proof-equivalence certificate. The WGSL path is wired through
//! `vyre-driver-wgpu`; targets without an installed emitter fail with
//! an actionable error instead of writing synthetic artifacts.
//!
//! Usage:
//!
//! ```sh
//! cargo xtask compile <program.vir> \
//!     [--to wgsl] [--to spirv] [--to ptx] [--to metal] [--to hlsl] \
//!     [--output-dir <dir>]
//! ```
//!
//! Every `--to TARGET` writes `<dir>/<fp>.<ext>` where `<fp>` is the
//! blake3 of the canonicalized IR (8 chars prefix for readability;
//! full 64-char form lives in the companion JSON manifest).

use std::fs;
use std::path::PathBuf;
use std::process;

/// Supported compile targets. Each implies a file extension +
/// emitter path. The emitters themselves live in backend crates;
/// this enum is the frozen taxonomy consumers pin against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Wgsl,
    Spirv,
    Ptx,
    Metal,
    Hlsl,
}

impl Target {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "wgsl" => Some(Self::Wgsl),
            "spirv" => Some(Self::Spirv),
            "ptx" => Some(Self::Ptx),
            "metal" => Some(Self::Metal),
            "hlsl" => Some(Self::Hlsl),
            _ => None,
        }
    }

    fn ext(self) -> &'static str {
        match self {
            Self::Wgsl => "wgsl",
            Self::Spirv => "spv",
            Self::Ptx => "ptx",
            Self::Metal => "metal",
            Self::Hlsl => "hlsl",
        }
    }
}

pub fn run(args: &[String]) {
    // Parse: compile <input> --to <t1> [--to <t2>] ... [--output-dir <d>]
    let mut idx = 2; // skip binary + "compile"
    if idx >= args.len() {
        eprintln!(
            "Fix: missing input wire file. Usage: cargo xtask compile <program.vir> --to <target>"
        );
        process::exit(2);
    }
    let input_path = PathBuf::from(&args[idx]);
    idx += 1;

    let mut targets: Vec<Target> = Vec::new();
    let mut out_dir = PathBuf::from("target/vyre-compile");

    while idx < args.len() {
        match args[idx].as_str() {
            "--to" => {
                idx += 1;
                if idx >= args.len() {
                    eprintln!("Fix: --to requires a target name");
                    process::exit(2);
                }
                match Target::parse(&args[idx]) {
                    Some(t) => targets.push(t),
                    None => {
                        eprintln!(
                            "Fix: unknown target '{}'. Supported: wgsl, spirv, ptx, metal, hlsl",
                            args[idx]
                        );
                        process::exit(2);
                    }
                }
                idx += 1;
            }
            "--output-dir" => {
                idx += 1;
                if idx >= args.len() {
                    eprintln!("Fix: --output-dir requires a path");
                    process::exit(2);
                }
                out_dir = PathBuf::from(&args[idx]);
                idx += 1;
            }
            other => {
                eprintln!("Fix: unknown arg '{other}'");
                process::exit(2);
            }
        }
    }

    if targets.is_empty() {
        eprintln!(
            "Fix: no --to targets specified. Must pass at least one (wgsl, spirv, ptx, metal, hlsl)."
        );
        process::exit(2);
    }

    let wire = match fs::read(&input_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Fix: can't read {}: {e}", input_path.display());
            process::exit(1);
        }
    };

    // Decode + canonicalize (content-addressed fingerprint basis).
    let program = match vyre_foundation::ir::Program::from_wire(&wire) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Fix: wire decode failed: {e}");
            process::exit(1);
        }
    };
    let canonical = vyre_foundation::transform::optimize::canonicalize::run(program);
    let canonical_wire = match canonical.to_wire() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Fix: canonical re-encode failed: {e}");
            process::exit(1);
        }
    };
    let fp = *blake3::hash(&canonical_wire).as_bytes();
    let mut fp_hex = String::with_capacity(fp.len() * 2);
    for b in &fp {
        use std::fmt::Write;
        write!(&mut fp_hex, "{b:02x}").expect("format to String never fails");
    }
    let fp_prefix = &fp_hex[..16];

    if let Err(e) = fs::create_dir_all(&out_dir) {
        eprintln!("Fix: can't create output dir {}: {e}", out_dir.display());
        process::exit(1);
    }

    // Emit each target through the owning backend crate. Targets
    // without an installed emitter fail before writing a misleading
    // artifact.
    for target in &targets {
        let artifact_path = out_dir.join(format!("{fp_prefix}.{}", target.ext()));
        let artifact = match emit_target(*target, &canonical) {
            Ok(bytes) => bytes,
            Err(message) => {
                eprintln!("{message}");
                process::exit(1);
            }
        };
        if let Err(e) = fs::write(&artifact_path, artifact) {
            eprintln!("Fix: can't write {}: {e}", artifact_path.display());
            process::exit(1);
        }
        println!("emitted: {}", artifact_path.display());
    }

    // Manifest: full fingerprint + target list for proof-of-equivalence.
    let manifest_path = out_dir.join(format!("{fp_prefix}.manifest.json"));
    let manifest = serde_json_manifest(&fp_hex, &targets);
    if let Err(e) = fs::write(&manifest_path, manifest) {
        eprintln!("Fix: can't write manifest: {e}");
        process::exit(1);
    }
    println!("manifest: {}", manifest_path.display());
}

fn emit_target(
    target: Target,
    canonical: &vyre_foundation::ir::Program,
) -> Result<Vec<u8>, String> {
    match target {
        Target::Wgsl => {
            let wgsl = vyre_driver_wgpu::lowering::lower(canonical)
                .map_err(|error| format!("Fix: WGSL lowering failed: {error}"))?;
            Ok(wgsl.into_bytes())
        }
        Target::Spirv => Err(
            "Fix: SPIR-V artifact emission has no installed xtask emitter; use vyre-driver-spirv directly or add its emitter here before requesting --to spirv."
                .to_string(),
        ),
        Target::Ptx => Err(
            "Fix: PTX artifact emission requires the CUDA backend crate to provide an emitter before --to ptx can be used."
                .to_string(),
        ),
        Target::Metal => Err(
            "Fix: Metal artifact emission requires the Metal backend crate to provide an emitter before --to metal can be used."
                .to_string(),
        ),
        Target::Hlsl => Err(
            "Fix: HLSL artifact emission requires a DXC backend emitter before --to hlsl can be used."
                .to_string(),
        ),
    }
}

fn serde_json_manifest(fp_hex: &str, targets: &[Target]) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str(&format!("  \"fingerprint\": \"{fp_hex}\",\n"));
    out.push_str("  \"targets\": [\n");
    for (i, t) in targets.iter().enumerate() {
        let comma = if i + 1 < targets.len() { "," } else { "" };
        out.push_str(&format!("    \"{}\"{comma}\n", t.ext()));
    }
    out.push_str("  ]\n");
    out.push_str("}\n");
    out
}
