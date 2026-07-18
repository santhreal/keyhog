use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() -> io::Result<()> {
    println!("cargo:rerun-if-changed=src/weights.bin");
    println!("cargo:rerun-if-changed=src/model_card.json");

    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "CARGO_MANIFEST_DIR is not set. Fix: run the build through Cargo",
        )
    })?;
    let manifest_dir = Path::new(&manifest_dir);
    stamp_source_tree_state(manifest_dir)?;
    stamp_gpu_driver_versions(manifest_dir)?;

    let out_dir = env::var_os("OUT_DIR").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "OUT_DIR is not set. Fix: run the build through Cargo so build-script outputs are available",
        )
    })?;
    let dest_path = Path::new(&out_dir).join("model_version.rs");

    let bytes = fs::read("src/weights.bin").map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("src/weights.bin is required for the shipped ML scorer: {error}"),
        )
    })?;
    let hash = fnv1a64(&bytes);
    let weights_hash = format!("{hash:016x}");
    let version_str = format!("moe-v1-{weights_hash}");

    let card_src = fs::read_to_string("src/model_card.json").map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("src/model_card.json is required beside weights.bin: {error}"),
        )
    })?;
    let card: serde_json::Value = serde_json::from_str(&card_src).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("src/model_card.json is not valid JSON: {error}"),
        )
    })?;

    let card_version = json_str(&card, "/model_version")?;
    if card_version != version_str {
        return Err(invalid_data(format!(
            "model_card.json model_version mismatch: card has {card_version}, weights.bin is {version_str}. Fix: rerun ml/train_classifier.py --write so weights.bin and model_card.json update together."
        )));
    }
    let card_hash = json_str(&card, "/weights_fnv1a64")?;
    if card_hash != weights_hash {
        return Err(invalid_data(format!(
            "model_card.json weights_fnv1a64 mismatch: card has {card_hash}, weights.bin is {weights_hash}"
        )));
    }

    let feature_count = json_u64(&card, "/feature_count")?;
    let recorded_date = json_str(&card, "/recorded_date")?;
    let synthetic_f1 = json_f64(&card, "/metrics/synthetic_heldout/f1")?;
    let synthetic_precision = json_f64(&card, "/metrics/synthetic_heldout/precision")?;
    let synthetic_recall = json_f64(&card, "/metrics/synthetic_heldout/recall")?;
    let real_f1 = json_f64(&card, "/metrics/real_heldout/real_f1")?;
    let real_precision = json_f64(&card, "/metrics/real_heldout/real_precision")?;
    let real_recall = json_f64(&card, "/metrics/real_heldout/real_recall")?;
    let real_floor_recall = json_f64(&card, "/metrics/real_heldout/recall_at_0_40_floor")?;
    let differential_status = json_str(
        &card,
        "/metrics/real_heldout/six_scanner_differential/status",
    )?;
    let (zero_recall_detectors, positive_detectors) = detector_recall_gaps(&card)?;
    let summary = format!(
        "recorded {recorded_date}; features {feature_count}; synthetic F1 {} / P {} / R {}; real F1 {} / P {} / R {} / recall@0.40 {}; zero-recall detectors {zero_recall_detectors}/{positive_detectors}; six-scanner differential {differential_status}",
        metric(synthetic_f1),
        metric(synthetic_precision),
        metric(synthetic_recall),
        metric(real_f1),
        metric(real_precision),
        metric(real_recall),
        metric(real_floor_recall),
    );

    fs::write(
        &dest_path,
        format!(
            "pub const MODEL_VERSION: &str = {};\n\
             pub const MODEL_CARD_JSON: &str = {};\n\
             pub const MODEL_CARD_SUMMARY: &str = {};\n",
            rust_string(&version_str),
            rust_string(&card_src),
            rust_string(&summary),
        ),
    )?;
    Ok(())
}

fn stamp_gpu_driver_versions(manifest_dir: &Path) -> io::Result<()> {
    let workspace_manifest = manifest_dir.join("../..").join("Cargo.toml");
    println!("cargo:rerun-if-changed={}", workspace_manifest.display());
    let source = fs::read_to_string(&workspace_manifest)?;
    let manifest = toml::from_str::<toml::Value>(&source).map_err(|error| {
        invalid_data(format!(
            "cannot parse workspace Cargo.toml for GPU driver identity: {error}"
        ))
    })?;
    for (dependency, variable) in [
        ("vyre-driver-cuda", "KEYHOG_VYRE_CUDA_VERSION"),
        ("vyre-driver-wgpu", "KEYHOG_VYRE_WGPU_VERSION"),
    ] {
        let version = manifest
            .get("workspace")
            .and_then(|value| value.get("dependencies"))
            .and_then(|value| value.get(dependency))
            .and_then(|value| value.get("version"))
            .and_then(toml::Value::as_str)
            .ok_or_else(|| {
                invalid_data(format!(
                    "workspace dependency {dependency} must declare an exact version for autoroute identity"
                ))
            })?;
        let exact = version.strip_prefix('=').ok_or_else(|| {
            invalid_data(format!(
                "workspace dependency {dependency} version {version:?} is not exact; use =x.y.z so autoroute identity is reproducible"
            ))
        })?;
        println!("cargo:rustc-env={variable}={exact}");
    }
    Ok(())
}

fn stamp_source_tree_state(manifest_dir: &Path) -> io::Result<()> {
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .unwrap_or(manifest_dir);
    let listed = git_output(
        workspace_root,
        &[
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
    );
    let state = match listed {
        Ok(paths) => {
            emit_source_watchers(workspace_root, &paths)?;
            match git_output(
                workspace_root,
                &["status", "--porcelain=v1", "--untracked-files=all"],
            ) {
                Ok(status) if status.is_empty() => "clean",
                Ok(_) => "dirty",
                Err(_) => "unknown",
            }
        }
        Err(_) => "unknown",
    };
    println!("cargo:rustc-env=KEYHOG_BUILD_SOURCE_TREE_STATE={state}");
    Ok(())
}

fn git_output(workspace_root: &Path, args: &[&str]) -> io::Result<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(workspace_root)
        .args(args)
        .output()
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("cannot run git for build source identity: {error}"),
            )
        })?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "git {} failed while recording build source identity: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(output.stdout)
}

fn emit_source_watchers(workspace_root: &Path, nul_paths: &[u8]) -> io::Result<()> {
    let mut directories = std::collections::BTreeSet::<PathBuf>::new();
    directories.insert(workspace_root.to_path_buf());
    for raw in nul_paths
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        let relative = std::str::from_utf8(raw).map_err(|error| {
            invalid_data(format!(
                "git returned a non-UTF-8 source path while recording build identity: {error}"
            ))
        })?;
        let path = workspace_root.join(relative);
        println!("cargo:rerun-if-changed={}", path.display());
        if let Some(parent) = path.parent() {
            directories.insert(parent.to_path_buf());
        }
    }
    for directory in directories {
        println!("cargo:rerun-if-changed={}", directory.display());
    }
    Ok(())
}

fn detector_recall_gaps(card: &serde_json::Value) -> io::Result<(usize, usize)> {
    let detectors = card
        .pointer("/metrics/real_heldout/per_detector")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            invalid_data(
                "model_card.json missing object field at JSON pointer /metrics/real_heldout/per_detector"
                    .to_string(),
            )
        })?;
    let mut positive = 0usize;
    let mut zero_recall = 0usize;
    for metric in detectors.values() {
        let n_pos = metric.get("n_pos").and_then(serde_json::Value::as_u64);
        if n_pos.unwrap_or(0) == 0 {
            continue;
        }
        positive += 1;
        let recall = metric
            .get("recall_at_0_40_floor")
            .and_then(serde_json::Value::as_f64)
            .ok_or_else(|| {
                invalid_data(
                    "positive-bearing per_detector metric omits recall_at_0_40_floor".to_string(),
                )
            })?;
        if recall == 0.0 {
            zero_recall += 1;
        }
    }
    Ok((zero_recall, positive))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in bytes {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn invalid_data(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn json_str<'a>(value: &'a serde_json::Value, pointer: &str) -> io::Result<&'a str> {
    value
        .pointer(pointer)
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            invalid_data(format!(
                "model_card.json missing string field at JSON pointer {pointer}"
            ))
        })
}

fn json_u64(value: &serde_json::Value, pointer: &str) -> io::Result<u64> {
    value
        .pointer(pointer)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            invalid_data(format!(
                "model_card.json missing unsigned integer field at JSON pointer {pointer}"
            ))
        })
}

fn json_f64(value: &serde_json::Value, pointer: &str) -> io::Result<f64> {
    value
        .pointer(pointer)
        .and_then(|v| v.as_f64())
        .ok_or_else(|| {
            invalid_data(format!(
                "model_card.json missing numeric field at JSON pointer {pointer}"
            ))
        })
}

fn metric(value: f64) -> String {
    let fixed = format!("{value:.3}");
    fixed
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_string()
}

fn rust_string(value: &str) -> String {
    format!("{value:?}")
}
