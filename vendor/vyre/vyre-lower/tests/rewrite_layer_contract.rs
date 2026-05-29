//! Test: rewrite layer contract.
use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("vyre-lower must live under workspace root")
        .to_path_buf()
}

fn rust_files(root: &Path) -> Vec<PathBuf> {
    fn visit(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                visit(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    let mut out = Vec::new();
    visit(root, &mut out);
    out
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| {
        panic!("failed to read {}: {error}", path.display());
    })
}

#[test]
fn foundation_program_optimizer_does_not_depend_on_lowered_descriptors() {
    let root = workspace_root().join("vyre-foundation/src/optimizer");
    let forbidden = [
        "KernelDescriptor",
        "KernelOp",
        "KernelBody",
        "vyre_lower::",
        "descriptor_const_fold",
        "descriptor_cse",
        "descriptor_dce",
    ];

    let mut offenders = Vec::new();
    for file in rust_files(&root) {
        let text = read(&file);
        for needle in forbidden {
            if text.contains(needle) {
                offenders.push(format!("{} contains {needle}", file.display()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "Program-IR optimizer must stay semantic and must not reach into lowered descriptor cleanup:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn descriptor_rewrite_cleanup_names_are_layer_prefixed() {
    let mod_rs = workspace_root().join("vyre-lower/src/rewrites/mod.rs");
    let text = read(&mod_rs);

    for name in ["const_fold", "cse", "dce"] {
        assert!(
            !text.contains(&format!("pub mod {name};")),
            "lowered descriptor cleanup must not expose an unprefixed `{name}` module"
        );
        assert!(
            !text.contains(&format!("pub use {name}::{name};")),
            "lowered descriptor cleanup must not re-export an unprefixed `{name}` function"
        );
    }

    for name in ["descriptor_const_fold", "descriptor_cse", "descriptor_dce"] {
        assert!(
            text.contains(&format!("pub mod {name};")),
            "missing descriptor-prefixed rewrite module `{name}`"
        );
        assert!(
            text.contains(&format!("pub use {name}::{name};")),
            "missing descriptor-prefixed rewrite re-export `{name}`"
        );
    }
}

#[test]
fn emit_and_driver_crates_do_not_host_program_optimizer_passes() {
    let root = workspace_root();
    let checked_roots = [
        root.join("vyre-emit-naga/src"),
        root.join("vyre-emit-ptx/src"),
        root.join("vyre-driver-wgpu/src"),
        root.join("vyre-driver-cuda/src"),
    ];
    let forbidden = [
        "ProgramPass",
        "PassScheduler",
        "pre_lowering::optimize",
        "optimizer::passes::const_fold",
        "optimizer::passes::fusion_cse",
        "fn fold_expr",
        "fold_binary_literal",
        "fold_unary_literal",
        "fold_cast_literal",
    ];

    let mut offenders = Vec::new();
    for checked_root in checked_roots {
        for file in rust_files(&checked_root) {
            let text = read(&file);
            for needle in forbidden {
                if text.contains(needle) {
                    offenders.push(format!("{} contains {needle}", file.display()));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "Emit/backend crates must not host Program-IR optimizer passes or duplicate Layer-1 constant folding:\n{}",
        offenders.join("\n")
    );
}
