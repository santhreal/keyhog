//! Gate `orchestrator`: no inline #[cfg(test)] in orchestrator module tree.

#[test]
fn orchestrator_no_inline_tests() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/orchestrator");
    for entry in std::fs::read_dir(dir).expect("read orchestrator dir") {
        let path = entry.expect("entry").path();
        if path.extension().is_some_and(|e| e == "rs") {
            let src = std::fs::read_to_string(&path).expect("read source");
            assert!(
                !src.lines().any(|l| l.trim().starts_with("#[cfg(test)]")),
                "{} must not host inline tests",
                path.display()
            );
        }
    }
}
