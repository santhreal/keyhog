//! Feature-parity oracle for the ML training pipeline.
//!
//! Reads one record per stdin line and prints the scanner's serve-path feature
//! vector for it, so `ml/parity_check.py` can assert the Python port in
//! `ml/features.py` computes byte-identical features. Without this check a
//! retrained model silently inherits train/serve skew.
//!
//! Line protocol (avoids a JSON dependency): six space-separated base64
//! (standard) fields:
//!   b64(text) b64(context) b64(known_prefixes) b64(secret_keywords)
//!   b64(test_keywords) b64(placeholder_keywords)
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
        assert_eq!(fields.len(), 6, "expected 6 base64 fields per line");
        let text = b64_decode(fields[0]);
        let context = b64_decode(fields[1]);
        let known_prefixes = parse_list(&b64_decode(fields[2]));
        let secret_keywords = parse_list(&b64_decode(fields[3]));
        let test_keywords = parse_list(&b64_decode(fields[4]));
        let placeholder_keywords = parse_list(&b64_decode(fields[5]));

        let features = keyhog_scanner::ml_scorer::compute_features_with_config(
            &text,
            &context,
            &known_prefixes,
            &secret_keywords,
            &test_keywords,
            &placeholder_keywords,
        );

        let rendered: Vec<String> = features.iter().map(|v| format!("{v:.9}")).collect();
        writeln!(out, "{}", rendered.join(" ")).expect("write line");
    }
    out.flush().expect("flush");
}
