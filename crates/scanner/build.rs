use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
#[path = "src/ml_scorer/service_vocab_build.rs"]
mod service_vocab_build;

fn main() -> io::Result<()> {
    println!("cargo:rerun-if-changed=src/weights.bin");
    println!("cargo:rerun-if-changed=src/model_card.json");
    println!("cargo:rerun-if-changed=src/quantized_moe.bin");
    println!("cargo:rerun-if-changed=data/english_bigram_logprob.bin");
    println!("cargo:rerun-if-changed=data/english_bigram_logprob.card.toml");

    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "CARGO_MANIFEST_DIR is not set. Fix: run the build through Cargo",
        )
    })?;
    let manifest_dir = Path::new(&manifest_dir);
    stamp_source_tree_state(manifest_dir)?;
    stamp_gpu_driver_versions(manifest_dir)?;
    verify_bigram_model_card()?;

    let out_dir = env::var_os("OUT_DIR").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "OUT_DIR is not set. Fix: run the build through Cargo so build-script outputs are available",
        )
    })?;
    generate_service_vocabulary(manifest_dir, Path::new(&out_dir))?;
    if env::var_os("CARGO_FEATURE_ENTROPY").is_some() {
        generate_cl100k_rank_table(manifest_dir, Path::new(&out_dir))?;
    }

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

    let quantized_bytes = fs::read("src/quantized_moe.bin").map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("src/quantized_moe.bin is required for quantized confidence scoring: {error}"),
        )
    })?;
    if quantized_bytes.len() < 60
        || &quantized_bytes[..8] != b"KHQMOE\0\x01"
        || u16::from_le_bytes([quantized_bytes[8], quantized_bytes[9]]) != 1
        || u16::from_le_bytes([quantized_bytes[10], quantized_bytes[11]]) != 1
        || u16::from_le_bytes([quantized_bytes[12], quantized_bytes[13]]) != 55
        || u16::from_le_bytes([quantized_bytes[14], quantized_bytes[15]]) != 6
        || u16::from_le_bytes([quantized_bytes[16], quantized_bytes[17]]) != 32
        || u16::from_le_bytes([quantized_bytes[18], quantized_bytes[19]]) != 16
        || quantized_bytes[20] != 7
        || quantized_bytes[21] != 1
        || quantized_bytes[22..24] != [0, 0]
    {
        return Err(invalid_data(
            "quantized_moe.bin has an unsupported header; regenerate the quantized model artifact",
        ));
    }
    let payload_len = u32::from_le_bytes([
        quantized_bytes[24],
        quantized_bytes[25],
        quantized_bytes[26],
        quantized_bytes[27],
    ]) as usize;
    let parameter_count = 6 * 55 + 6 + 6 * (32 * 55 + 32 + 16 * 32 + 16 + 16 + 1);
    let expected_payload_len = parameter_count * std::mem::size_of::<i16>();
    if payload_len != expected_payload_len || quantized_bytes.len() != 60 + payload_len {
        return Err(invalid_data(
            "quantized_moe.bin parameter count or artifact length is invalid",
        ));
    }
    let expected_payload_digest = &quantized_bytes[28..60];
    let actual_payload_digest = Sha256::digest(&quantized_bytes[60..]);
    if expected_payload_digest != &actual_payload_digest[..] {
        return Err(invalid_data(
            "quantized_moe.bin payload digest mismatch; regenerate the quantized model artifact",
        ));
    }
    let max_parameter_magnitude = quantized_bytes[60..]
        .chunks_exact(std::mem::size_of::<i16>())
        .map(|pair| i64::from(i16::from_le_bytes([pair[0], pair[1]])).abs())
        .max()
        .unwrap_or(0);
    let maximum_dense_accumulator = 55i64 * (i64::from(i16::MAX) + 1) * max_parameter_magnitude
        + 128 * max_parameter_magnitude
        + 64;
    if maximum_dense_accumulator > i64::from(i32::MAX) {
        return Err(invalid_data(format!(
            "quantized_moe.bin parameter magnitude {max_parameter_magnitude} exceeds the VYRE i32 arithmetic bound; retrain with a bounded quantization scale"
        )));
    }
    let quantized_digest = hex_lower(&Sha256::digest(&quantized_bytes));
    let card_quantized_digest = json_str(&card, "/quantized_serving/artifact_sha256")?;
    if card_quantized_digest != quantized_digest {
        return Err(invalid_data(format!(
            "model_card.json quantized artifact mismatch: card has {card_quantized_digest}, artifact is {quantized_digest}"
        )));
    }
    if json_u64(&card, "/quantized_serving/format_version")? != 1
        || json_u64(&card, "/quantized_serving/feature_schema_version")? != 1
        || json_u64(&card, "/quantized_serving/fractional_bits")? != 7
        || json_str(&card, "/quantized_serving/rounding")? != "nearest-ties-away-from-zero"
    {
        return Err(invalid_data(
            "model_card.json quantized serving ABI is stale; regenerate the model card",
        ));
    }

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
fn generate_cl100k_rank_table(manifest_dir: &Path, out_dir: &Path) -> io::Result<()> {
    let source = manifest_dir.join("data/cl100k_base.tiktoken");
    println!("cargo:rerun-if-changed={}", source.display());
    let encoded = fs::read_to_string(&source).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "{} is required for entropy BPE scoring: {error}",
                source.display()
            ),
        )
    })?;

    let mut tokens = Vec::<(Vec<u8>, u32)>::new();
    let mut seen_tokens = std::collections::HashSet::<Vec<u8>>::new();
    let mut seen_ranks = std::collections::HashSet::<u32>::new();
    for (line_index, line) in encoded.lines().enumerate() {
        let line_number = line_index + 1;
        let mut fields = line.split_ascii_whitespace();
        let token = fields.next().ok_or_else(|| {
            invalid_data(format!(
                "{}:{line_number}: missing base64 token",
                source.display()
            ))
        })?;
        let rank = fields
            .next()
            .ok_or_else(|| {
                invalid_data(format!(
                    "{}:{line_number}: missing token rank",
                    source.display()
                ))
            })?
            .parse::<u32>()
            .map_err(|error| {
                invalid_data(format!(
                    "{}:{line_number}: invalid token rank: {error}",
                    source.display()
                ))
            })?;
        if fields.next().is_some() {
            return Err(invalid_data(format!(
                "{}:{line_number}: unexpected field after token rank",
                source.display()
            )));
        }
        let token = base64::engine::general_purpose::STANDARD
            .decode(token)
            .map_err(|error| {
                invalid_data(format!(
                    "{}:{line_number}: invalid base64 token: {error}",
                    source.display()
                ))
            })?;
        if token.is_empty() {
            return Err(invalid_data(format!(
                "{}:{line_number}: empty BPE token is invalid",
                source.display()
            )));
        }
        if !seen_tokens.insert(token.clone()) {
            return Err(invalid_data(format!(
                "{}:{line_number}: duplicate BPE token",
                source.display()
            )));
        }
        if !seen_ranks.insert(rank) {
            return Err(invalid_data(format!(
                "{}:{line_number}: duplicate BPE rank {rank}",
                source.display()
            )));
        }
        tokens.push((token, rank));
    }
    if tokens.len() != 100_256 || seen_ranks.iter().copied().max() != Some(100_255) {
        return Err(invalid_data(format!(
            "{} must contain exactly the contiguous cl100k ranks 0..=100255; found {} rows",
            source.display(),
            tokens.len()
        )));
    }
    if !(0..=100_255).all(|rank| seen_ranks.contains(&rank)) {
        return Err(invalid_data(format!(
            "{} has a gap in the cl100k rank range",
            source.display()
        )));
    }

    tokens.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    let mut token_bytes = Vec::new();
    let mut offsets = Vec::with_capacity(tokens.len() + 1);
    let mut ranks = Vec::with_capacity(tokens.len());
    offsets.extend_from_slice(&0_u32.to_le_bytes());
    for (token, rank) in &tokens {
        token_bytes.extend_from_slice(token);
        let end = u32::try_from(token_bytes.len()).map_err(|_| {
            invalid_data("cl100k token bytes exceed the u32 packed-table limit".to_owned())
        })?;
        offsets.extend_from_slice(&end.to_le_bytes());
        ranks.extend_from_slice(&rank.to_le_bytes());
    }

    let mut prefixes = Vec::with_capacity(257 * std::mem::size_of::<u32>());
    let mut index = 0usize;
    for first in 0_u16..=255 {
        prefixes.extend_from_slice(
            &u32::try_from(index)
                .map_err(|_| invalid_data("cl100k token count exceeds u32".to_owned()))?
                .to_le_bytes(),
        );
        while index < tokens.len() && u16::from(tokens[index].0[0]) == first {
            index += 1;
        }
    }
    prefixes.extend_from_slice(
        &u32::try_from(tokens.len())
            .map_err(|_| invalid_data("cl100k token count exceeds u32".to_owned()))?
            .to_le_bytes(),
    );

    fs::write(out_dir.join("cl100k_token_bytes.bin"), token_bytes)?;
    fs::write(out_dir.join("cl100k_offsets.bin"), offsets)?;
    fs::write(out_dir.join("cl100k_ranks.bin"), ranks)?;
    fs::write(out_dir.join("cl100k_prefixes.bin"), prefixes)?;
    Ok(())
}

fn generate_service_vocabulary(manifest_dir: &Path, out_dir: &Path) -> io::Result<()> {
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| {
            invalid_data("scanner manifest is not under the workspace crates directory".to_owned())
        })?;
    let detector_dir = workspace_root.join("detectors");
    println!("cargo:rerun-if-changed={}", detector_dir.display());

    struct DetectorRow {
        id: String,
        generic_family: bool,
        keywords: Vec<String>,
    }

    let mut paths = fs::read_dir(&detector_dir)
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "reading detector corpus {}: {error}",
                    detector_dir.display()
                ),
            )
        })?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "toml")
        })
        .collect::<Vec<_>>();
    paths.sort();

    let mut rows = Vec::with_capacity(paths.len());
    for path in paths {
        let source = fs::read_to_string(&path).map_err(|error| {
            io::Error::new(error.kind(), format!("reading {}: {error}", path.display()))
        })?;
        let document = toml::from_str::<toml::Value>(&source).map_err(|error| {
            invalid_data(format!("parsing detector {}: {error}", path.display()))
        })?;
        let Some(detector) = document.get("detector").and_then(toml::Value::as_table) else {
            continue;
        };
        let id = detector
            .get("id")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| invalid_data(format!("{} detector omits id", path.display())))?
            .to_owned();
        let keywords = detector
            .get("keywords")
            .and_then(toml::Value::as_array)
            .ok_or_else(|| invalid_data(format!("{} detector omits keywords", path.display())))?
            .iter()
            .map(|keyword| {
                keyword.as_str().map(str::to_owned).ok_or_else(|| {
                    invalid_data(format!(
                        "{} detector has a non-string keyword",
                        path.display()
                    ))
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        let generic_family = detector
            .get("kind")
            .and_then(toml::Value::as_str)
            .is_some_and(|kind| kind == "phase2-generic")
            || detector.contains_key("entropy_policy_priority");
        rows.push(DetectorRow {
            id,
            generic_family,
            keywords,
        });
    }

    let vocabulary = service_vocab_build::build_service_vocabulary(rows.iter().map(|row| {
        service_vocab_build::ServiceVocabularyDetector {
            id: &row.id,
            generic_family: row.generic_family,
            keywords: &row.keywords,
        }
    }));
    if vocabulary.is_empty() {
        return Err(invalid_data(
            "detector corpus produced an empty ML service vocabulary".to_owned(),
        ));
    }
    let mut generated = String::from("&[\n");
    for keyword in vocabulary {
        generated.push_str("    ");
        generated.push_str(&rust_string(&keyword));
        generated.push_str(",\n");
    }
    generated.push_str("]\n");
    fs::write(out_dir.join("ml_service_vocabulary.rs"), generated)
}

/// Verify `data/english_bigram_logprob.bin` against its provenance card.
///
/// The table is `include_bytes!`-embedded and drives every dictionary-vs-random
/// verdict in the generic bridge, so a truncated or regenerated-but-unrecorded
/// file must fail the BUILD rather than silently shift suppression. Mirrors the
/// `weights.bin` / `model_card.json` contract above.
fn verify_bigram_model_card() -> io::Result<()> {
    let bytes = fs::read("data/english_bigram_logprob.bin").map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("data/english_bigram_logprob.bin is required by the randomness discriminator: {error}"),
        )
    })?;
    let card_src =
        fs::read_to_string("data/english_bigram_logprob.card.toml").map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                "data/english_bigram_logprob.card.toml is required beside the bigram table: {error}"
            ),
            )
        })?;
    let card: toml::Value = toml::from_str(&card_src).map_err(|error| {
        invalid_data(format!(
            "data/english_bigram_logprob.card.toml is not valid TOML: {error}"
        ))
    })?;
    let model = card.get("bigram_model").ok_or_else(|| {
        invalid_data("english_bigram_logprob.card.toml is missing [bigram_model]".to_string())
    })?;
    let card_int = |key: &str| -> io::Result<i64> {
        model
            .get(key)
            .and_then(toml::Value::as_integer)
            .ok_or_else(|| {
                invalid_data(format!(
                    "english_bigram_logprob.card.toml [bigram_model].{key} must be an integer"
                ))
            })
    };
    let schema_version = card_int("schema_version")?;
    if schema_version != 1 {
        return Err(invalid_data(format!(
            "english_bigram_logprob.card.toml schema_version {schema_version} is unsupported; \
             this build understands version 1"
        )));
    }
    let expected_bytes = card_int("rows")? * card_int("columns")? * 4;
    let declared_bytes = card_int("bytes")?;
    if declared_bytes != expected_bytes {
        return Err(invalid_data(format!(
            "english_bigram_logprob.card.toml declares {declared_bytes} bytes but rows*columns*4 \
             is {expected_bytes}"
        )));
    }
    if i64::try_from(bytes.len()).unwrap_or(i64::MAX) != expected_bytes {
        return Err(invalid_data(format!(
            "english_bigram_logprob.bin is {} bytes, the card requires {expected_bytes}. Fix: \
             regenerate with ml/gen_bigram_model.py and update the card.",
            bytes.len()
        )));
    }
    let digest = format!("{:016x}", fnv1a64(&bytes));
    let card_digest = model
        .get("bytes_fnv1a64")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| {
            invalid_data(
                "english_bigram_logprob.card.toml [bigram_model].bytes_fnv1a64 must be a string"
                    .to_string(),
            )
        })?;
    if card_digest != digest {
        return Err(invalid_data(format!(
            "english_bigram_logprob.card.toml bytes_fnv1a64 mismatch: card has {card_digest}, \
             the table is {digest}. Fix: rerun ml/gen_bigram_model.py and record the new digest."
        )));
    }
    Ok(())
}

fn stamp_gpu_driver_versions(manifest_dir: &Path) -> io::Result<()> {
    let crate_manifest_path = manifest_dir.join("Cargo.toml");
    println!("cargo:rerun-if-changed={}", crate_manifest_path.display());
    let crate_manifest = parse_manifest(&crate_manifest_path, "scanner crate")?;
    let workspace_manifest_path = manifest_dir.join("../..").join("Cargo.toml");
    let workspace_manifest = if workspace_manifest_path.is_file() {
        println!(
            "cargo:rerun-if-changed={}",
            workspace_manifest_path.display()
        );
        Some(parse_manifest(&workspace_manifest_path, "workspace")?)
    } else {
        None
    };

    for (dependency, variable) in [
        ("vyre-driver-cuda", "KEYHOG_VYRE_CUDA_VERSION"),
        ("vyre-driver-wgpu", "KEYHOG_VYRE_WGPU_VERSION"),
        ("vyre-driver-metal", "KEYHOG_VYRE_METAL_VERSION"),
    ] {
        let version = dependency_version(&crate_manifest, dependency)
            .or_else(|| {
                workspace_manifest
                    .as_ref()
                    .and_then(|manifest| workspace_dependency_version(manifest, dependency))
            })
            .ok_or_else(|| {
                invalid_data(format!(
                    "dependency {dependency} must declare an exact version in the packaged crate or workspace manifest for autoroute identity"
                ))
            })?;
        let exact = version.strip_prefix('=').ok_or_else(|| {
            invalid_data(format!(
                "dependency {dependency} version {version:?} is not exact; use =x.y.z so autoroute identity is reproducible"
            ))
        })?;
        println!("cargo:rustc-env={variable}={exact}");
    }
    Ok(())
}

fn parse_manifest(path: &Path, role: &str) -> io::Result<toml::Value> {
    let source = fs::read_to_string(path)?;
    toml::from_str(&source).map_err(|error| {
        invalid_data(format!(
            "cannot parse {role} Cargo.toml at {} for GPU driver identity: {error}",
            path.display()
        ))
    })
}

fn dependency_version<'a>(manifest: &'a toml::Value, dependency: &str) -> Option<&'a str> {
    manifest
        .get("dependencies")
        .and_then(|value| value.get(dependency))
        .and_then(|value| value.get("version"))
        .and_then(toml::Value::as_str)
        .or_else(|| {
            manifest
                .get("target")
                .and_then(toml::Value::as_table)
                .and_then(|targets| {
                    targets.values().find_map(|target| {
                        target
                            .get("dependencies")
                            .and_then(|value| value.get(dependency))
                            .and_then(|value| value.get("version"))
                            .and_then(toml::Value::as_str)
                    })
                })
        })
}

fn workspace_dependency_version<'a>(
    manifest: &'a toml::Value,
    dependency: &str,
) -> Option<&'a str> {
    manifest
        .get("workspace")
        .and_then(|value| value.get("dependencies"))
        .and_then(|value| value.get(dependency))
        .and_then(|value| value.get("version"))
        .and_then(toml::Value::as_str)
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

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
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
