//! Feature-parity oracle for the ML training pipeline.
//!
//! Reads one record per stdin line and prints the scanner's serve-path feature
//! vector for it, so `ml/parity_check.py` can assert the Python parity port in
//! `ml/feature_parity.py` computes byte-identical features. Without this check a
//! retrained model silently inherits train/serve skew.
//!
//! Line protocol (avoids a JSON dependency): eight space-separated base64
//! (standard) fields:
//!   b64(text) b64(context) b64(known_prefixes) b64(secret_keywords)
//!   b64(test_keywords) b64(placeholder_keywords) b64(detector_id)
//!   b64(candidate_channel)
//! Each list field decodes to a `\n`-joined string (empty => empty list).
//! Output: one line per record, NUM_FEATURES space-separated f32 (`{:.9}`).

use base64::Engine;
use std::io::{self, BufRead, Write};

fn b64_decode(field: &str) -> String {
    if field.is_empty() {
        return String::new();
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(field.as_bytes())
        .expect("valid base64 field");
    String::from_utf8(bytes).expect("valid utf-8 field")
}

fn parse_list(decoded: &str) -> Vec<String> {
    if decoded.is_empty() {
        return Vec::new();
    }
    decoded.split('\n').map(|s| s.to_string()).collect()
}

fn resolve_detector(id: &str) -> Option<&'static keyhog_core::DetectorSpec> {
    // LAW10: an ID without the optional channel suffix is already the complete detector ID; no lookup failure is discarded.
    let finding_id = id.split(':').next().unwrap_or(id);
    keyhog_core::detector_spec_by_id(finding_id).or_else(|| {
        keyhog_core::embedded_detector_specs().iter().find(|spec| {
            spec.entropy_fallback
                .as_ref()
                .is_some_and(|fallback| fallback.id == finding_id)
        })
    })
}

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    for line in stdin.lock().lines() {
        let line = line.expect("read line");
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split(' ').collect();
        assert_eq!(fields.len(), 8, "expected 8 base64 fields per line");
        let text = b64_decode(fields[0]);
        let context = b64_decode(fields[1]);
        let known_prefixes = parse_list(&b64_decode(fields[2]));
        let secret_keywords = parse_list(&b64_decode(fields[3]));
        let test_keywords = parse_list(&b64_decode(fields[4]));
        let placeholder_keywords = parse_list(&b64_decode(fields[5]));
        let detector_id = b64_decode(fields[6]);
        let detector = resolve_detector(&detector_id)
            // LAW10: this diagnostic exporter aborts with the unknown ID; it cannot emit features under a substituted detector policy.
            .unwrap_or_else(|| panic!("unknown detector or entropy owner {detector_id:?}"));
        let channel = match b64_decode(fields[7]).as_str() {
            "pattern" => keyhog_scanner::ml_scorer::MlCandidateChannel::Pattern,
            "entropy" => keyhog_scanner::ml_scorer::MlCandidateChannel::Entropy,
            other => panic!("unknown ML candidate channel {other:?}"),
        };

        let features = keyhog_scanner::ml_scorer::compute_features_for_detector_with_config(
            &text,
            &context,
            &known_prefixes,
            &secret_keywords,
            &test_keywords,
            &placeholder_keywords,
            detector,
            channel,
        );

        let rendered: Vec<String> = features.iter().map(|v| format!("{v:.9}")).collect();
        writeln!(out, "{}", rendered.join(" ")).expect("write line");
    }
    out.flush().expect("flush");
}
