//! `state_file::read_capped` — the shared size-capped state-artifact reader used
//! by calibration, the merkle index, and the rule/allowlist config loaders.
//!
//! Migrated out of an inline `#[cfg(test)] mod tests` in `src/state_file.rs`
//! (Santh no-inline-tests contract). `read_capped` is `pub(crate)`, so these
//! drive it through the `CoreTestApi` test shim rather than reaching a private
//! item directly.

use keyhog_core::testing::{CoreTestApi, TestApi};
use std::io::Write;

fn tmp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("keyhog_state_file_{name}_{}", std::process::id()));
    std::fs::File::create(&p).unwrap().write_all(bytes).unwrap();
    p
}

#[test]
fn within_cap_reads_exact_bytes() {
    let p = tmp("ok", b"alpha-beta");
    let got = TestApi
        .read_capped(&p, 64, "calibration")
        .expect("within cap must read");
    assert_eq!(got, b"alpha-beta");
    std::fs::remove_file(&p).ok();
}

#[test]
fn oversized_file_is_refused_with_invalid_data() {
    // Adversarial: a hostile/corrupt state artifact larger than the cap must be
    // refused (not read into memory), with a message telling the operator to
    // delete the cache.
    let p = tmp("big", &vec![b'x'; 128]);
    let err = TestApi
        .read_capped(&p, 16, "merkle-index")
        .expect_err("oversized must be refused");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("exceeds 16 byte cap"));
    std::fs::remove_file(&p).ok();
}
