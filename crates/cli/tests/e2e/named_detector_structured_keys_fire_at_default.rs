//! E2E regression: service-anchored detectors whose credential is a
//! STRUCTURED shape (UUID, long hex) must fire at DEFAULT settings - NOT
//! only under `--no-ml`. The ML confidence path used to slam such matches
//! to 0.1 (generic probabilistic-promise gate) or *0.1 (char-diversity
//! penalty), below the 0.3 report floor, silently deleting ~112 named
//! detectors (Heroku / Braze / Codecov / Consul / Linode UUID & hex keys).
//! A named anchor is positive evidence; the shape heuristics that gate the
//! anchorless generic path must never bury it. This test drives the real
//! binary with NO flags so a regression in the default scoring path is caught.

use crate::e2e::support::scan_path;
use tempfile::TempDir;

/// Build a random-ish UUID-v-shaped value (high entropy, lowercase hex).
fn uuid_like(seed: u64) -> String {
    // Simple deterministic LCG so the value is stable but high-entropy.
    let mut s = seed;
    let mut hex = String::new();
    while hex.len() < 32 {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        hex.push_str(&format!("{:08x}", (s >> 32) as u32));
    }
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn hex64(seed: u64) -> String {
    let mut s = seed;
    let mut hex = String::new();
    while hex.len() < 64 {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        hex.push_str(&format!("{:08x}", (s >> 32) as u32));
    }
    hex[..64].to_string()
}

#[test]
fn named_uuid_and_hex_detectors_fire_without_no_ml_flag() {
    let dir = TempDir::new().expect("tempdir");
    // (filename, content, detector_id that MUST appear)
    let braze = format!("BRAZE_API_KEY={}\n", uuid_like(0x1111));
    let heroku = format!("HEROKU_API_KEY={}\n", uuid_like(0x2222));
    let codecov = format!("CODECOV_TOKEN={}\n", uuid_like(0x3333));
    let consul = format!("CONSUL_HTTP_TOKEN={}\n", uuid_like(0x4444));
    let linode = format!("LINODE_TOKEN={}\n", hex64(0x5555));
    let cases = [
        ("braze.env", &braze, "braze-api-key"),
        ("heroku.env", &heroku, "heroku-api-key"),
        ("codecov.env", &codecov, "codecov-token"),
        ("consul.env", &consul, "consul-acl-token"),
        ("linode.env", &linode, "linode-pat"),
    ];
    for (name, content, _) in &cases {
        std::fs::write(dir.path().join(name), content).unwrap();
    }

    // DEFAULT settings - no --no-ml, no --min-confidence override.
    let out = scan_path(dir.path(), &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(1),
        "structured-credential named detectors must surface a finding at default settings; stdout:\n{stdout}"
    );
    for (_, _, det) in &cases {
        assert!(
            stdout.contains(det),
            "named detector `{det}` must fire at DEFAULT settings (ML path must not bury a \
             service-anchored UUID/hex credential below the 0.3 report floor); stdout:\n{stdout}"
        );
    }
}
