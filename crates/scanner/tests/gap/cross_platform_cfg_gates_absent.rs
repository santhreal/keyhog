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

    for file in [
        "src/suppression/api.rs",
        "src/engine/phase2_entropy/gates.rs",
    ] {
        let body = src(file);
        assert!(
            body.contains("platform_compat::path_basename_bytes"),
            "{file} must use the shared byte-basename owner"
        );
        assert!(
            !body.contains("rposition(|&b| b == b'/' || b == b'\\\\')"),
            "{file} reintroduced local byte basename extraction"
        );
    }

    for file in [
        "src/context/inference.rs",
        "src/confidence/penalties.rs",
        "src/suppression/decision.rs",
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
