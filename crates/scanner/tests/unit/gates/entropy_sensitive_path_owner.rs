fn read_src(relative: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "{} must be readable for source ownership gate: {error}",
            path.display()
        )
    })
}

fn uncommented(src: &str) -> String {
    src.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn entropy_thresholding_uses_confidence_sensitive_path_owner() {
    let entropy_scanner = uncommented(&read_src("entropy/scanner.rs"));
    assert!(
        !entropy_scanner.contains("fn is_sensitive_file("),
        "entropy/scanner.rs must not own a duplicate sensitive-file classifier"
    );

    let entropy_mod = uncommented(&read_src("entropy/mod.rs"));
    assert!(
        !entropy_mod.contains("is_sensitive_file"),
        "entropy/mod.rs must not re-export duplicate sensitive-file classification"
    );

    let phase2_entropy = uncommented(&read_src("engine/phase2_entropy.rs"));
    assert!(
        phase2_entropy.contains("crate::confidence::is_sensitive_path"),
        "phase2 entropy thresholding must use confidence::is_sensitive_path"
    );
    assert!(
        !phase2_entropy.contains("crate::entropy::is_sensitive_file"),
        "phase2 entropy thresholding must not call an entropy-local sensitive-file helper"
    );
}
