//! KH-GAP-121: scanner path compatibility must be wired into production paths.
//!
//! A previous test counted `cfg` markers in `src/`, which allowed an unreachable
//! `platform_compat` module and a decorative string-replace test. This contract
//! pins the actual owner: all path component/basename decisions used by context,
//! confidence, and base64 raw-file suppression must call `platform_compat`.

use std::path::PathBuf;

fn src(path: &str) -> String {
    let full = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
    std::fs::read_to_string(&full).unwrap_or_else(|error| {
        panic!("read {} failed: {error}", full.display());
    })
}

#[test]
fn scanner_path_compat_owner_is_declared_and_used() {
    let lib = src("src/lib.rs");
    assert!(
        lib.contains("pub(crate) mod platform_compat;"),
        "scanner path owner must be declared in src/lib.rs"
    );

    let path_owner = src("src/platform_compat/path.rs");
    assert!(path_owner.contains("fn path_basename("));
    assert!(path_owner.contains("fn path_basename_bytes("));
    assert!(path_owner.contains("fn path_component_matches("));

    let context = src("src/context/inference.rs");
    assert!(
        context.contains("platform_compat::path_basename")
            && context.contains("platform_compat::path_has_any_component"),
        "context test-file detection must use the platform path owner"
    );

    let confidence = src("src/confidence/penalties.rs");
    assert!(
        confidence.contains("platform_compat::path_component_matches"),
        "path confidence penalties must use the platform path owner"
    );

    let path_filter = src("src/suppression/path_filter.rs");
    assert!(
        path_filter.contains("platform_compat::path_basename_bytes"),
        "raw-base64 file path suppression must use the shared byte-basename owner"
    );
    assert!(
        !path_filter.contains("rposition(|&b| b == b'/' || b == b'\\\\')")
            && !path_filter.contains("rsplit(['/', '\\\\']).next"),
        "path_filter reintroduced local basename extraction"
    );

    let suppression_api = src("src/suppression/api.rs");
    assert!(
        suppression_api.contains("looks_like_raw_base64_file_path(path)"),
        "suppression/api.rs must delegate raw-base64 path policy to path_filter"
    );
    let entropy_gates = src("src/engine/phase2_entropy/gates.rs");
    assert!(
        entropy_gates.contains("looks_like_entropy_raw_base64_file_path(chunk.metadata.path.as_deref())"),
        "phase2 entropy gates must delegate raw-base64 path policy to path_filter"
    );

    for file in [
        "src/context/inference.rs",
        "src/confidence/penalties.rs",
        "src/suppression/decision.rs",
        "src/suppression/path_filter.rs",
    ] {
        let body = src(file);
        assert!(
            !body.contains("split(['/', '\\\\']).any"),
            "{file} reintroduced local path-component splitting"
        );
        assert!(
            !body.contains("rsplit(['/', '\\\\']).next"),
            "{file} reintroduced local basename extraction"
        );
    }
}

#[test]
fn scanner_path_compat_has_no_orphan_line_ending_module() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/platform_compat");
    assert!(
        !root.join("io.rs").exists(),
        "platform_compat/io.rs was decorative and unreachable; line offsets are owned by pipeline"
    );
}
