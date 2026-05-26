//! Detector-spec hash digest for merkle cache invalidation.

use crate::spec::DetectorSpec;

/// Compute a stable BLAKE3 digest over the canonical detector set so a
/// later scan can detect that detectors changed.
pub fn compute_spec_hash(detectors: &[DetectorSpec]) -> [u8; 32] {
    let mut keys: Vec<String> = detectors
        .iter()
        .flat_map(|d| {
            let mut entries =
                Vec::with_capacity(2 + d.patterns.len() + d.companions.len() + d.keywords.len());
            entries.push(format!("id:{}", d.id));
            entries.push(format!("sev:{:?}", d.severity));
            for p in &d.patterns {
                entries.push(format!(
                    "p:{}|g:{}",
                    p.regex,
                    p.group.map(|g| g.to_string()).unwrap_or_default()
                ));
            }
            for c in &d.companions {
                entries.push(format!(
                    "c:{}|{}|w:{}|r:{}",
                    c.name, c.regex, c.within_lines, c.required
                ));
            }
            let mut kws: Vec<&String> = d.keywords.iter().collect();
            kws.sort();
            for k in kws {
                entries.push(format!("kw:{}:{}", d.id, k));
            }
            entries
        })
        .collect();
    keys.sort();
    let mut hasher = blake3::Hasher::new();
    for k in keys {
        hasher.update(k.as_bytes());
        hasher.update(b"\n");
    }
    *hasher.finalize().as_bytes()
}

pub(crate) fn hex_encode(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

pub(crate) fn hex_to_array(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}
