use std::env;
use std::fs;
use std::io;
use std::path::Path;

fn main() -> io::Result<()> {
    println!("cargo:rerun-if-changed=src/weights.bin");
    println!("cargo:rerun-if-changed=src/model_card.json");

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
    let real_recall = json_f64(&card, "/metrics/real_heldout/recall_at_0_40_floor")?;
    let summary = format!(
        "recorded {recorded_date}; features {feature_count}; synthetic F1 {} / P {} / R {}; real recall@0.40 {}",
        metric(synthetic_f1),
        metric(synthetic_precision),
        metric(synthetic_recall),
        metric(real_recall),
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
