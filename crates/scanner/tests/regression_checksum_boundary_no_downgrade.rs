//! Regression: a boundary extension must never DOWNGRADE an already-valid
//! checksum.
//!
//! `extend_known_prefix_credential` greedily extends a known-prefix token's
//! match boundary (provider-token bytes + up to two trailing base64 `=`
//! padding chars). When a checksum-valid token like a PyPI token
//! (`pypi-<base64url>`, checksum-Valid) is immediately followed by a `=`
//! separator, e.g. `pypi-…MNH="…"`: the padding-extension appended that `=`,
//! turning the canonical 105-char token into a 106-char value that FAILS the
//! PyPI checksum and was dropped as `checksum_invalid`. The real secret was
//! lost. (Surfaced by the unicode swap-invariance gate: homoglyphing the
//! companion context around a standalone-sufficient pypi credential left a
//! trailing `=` abutting the token.)
//!
//! The fix reverts the extension whenever it downgrades a Valid checksum to a
//! non-Valid one, so the canonical token still surfaces.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::sync::OnceLock;

fn scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
        CompiledScanner::compile(detectors).expect("compile scanner")
    })
}

fn matches_for(body: &str) -> Vec<(String, String)> {
    let chunk = Chunk {
        data: body.into(),
        metadata: ChunkMetadata {
            source_type: "checksum-boundary-regression".into(),
            path: Some("notes/checksum-boundary-probe.txt".into()),
            ..Default::default()
        },
    };
    scanner().clear_fragment_cache();
    scanner()
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .into_iter()
        .flatten()
        .map(|m| (m.detector_id.to_string(), m.credential.as_str().to_string()))
        .collect()
}

// A checksum-VALID PyPI token (verified by checksum/pypi.rs: 105 chars,
// `pypi-` + base64url body decoding to >= 32 bytes).
const VALID_PYPI: &str =
    "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH";

#[test]
fn pypi_token_followed_by_equals_separator_surfaces_canonically() {
    // The valid token is immediately followed by `="…"`. The padding-extension
    // would append the `=` and break the checksum; the token must still surface
    // with its CANONICAL boundary (no trailing `=`).
    let matches = matches_for(&format!("{VALID_PYPI}=\"x\""));
    let pypi: Vec<&String> = matches
        .iter()
        .filter(|(id, _)| id == "pypi-api-token")
        .map(|(_, cred)| cred)
        .collect();
    assert!(
        pypi.iter().any(|c| c.as_str() == VALID_PYPI),
        "the canonical valid pypi token must surface; matches={matches:?}"
    );
    assert!(
        !pypi.iter().any(|c| c.ends_with('=')),
        "no surfaced pypi credential may carry the trailing `=` separator; matches={matches:?}"
    );
}

#[test]
fn bare_pypi_token_still_surfaces() {
    // Control: the token on its own (no trailing separator) surfaces unchanged.
    let matches = matches_for(VALID_PYPI);
    assert!(
        matches
            .iter()
            .any(|(id, cred)| id == "pypi-api-token" && cred == VALID_PYPI),
        "the bare valid pypi token must surface; matches={matches:?}"
    );
}
