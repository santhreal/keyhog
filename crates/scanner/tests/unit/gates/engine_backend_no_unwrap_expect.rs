//! Gate `engine::backend`: no .unwrap( / .expect( in production source lines.

use super::support::unwrap_expect_offenders;

#[test]
fn engine_backend_no_unwrap_expect() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/backend");
    for entry in std::fs::read_dir(dir).expect("read backend dir") {
        let entry = entry.expect("valid entry");
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "rs") {
            let src = std::fs::read_to_string(&path).expect("source readable");
            let offenders = unwrap_expect_offenders(&src);
            assert!(
                offenders.is_empty(),
                "engine::backend/{}: unwrap/expect in production source at {:?}",
                path.file_name().unwrap().to_string_lossy(),
                offenders.iter().take(5).collect::<Vec<_>>()
            );
        }
    }
}
