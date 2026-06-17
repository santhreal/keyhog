//! `.pdf` must route through the dedicated PDF extractor, not through the
//! Tier-B binary-extension denylist.

fn read(rel: &str) -> String {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

#[test]
fn pdf_not_in_skip_extensions_and_has_structured_route() {
    let rules = read("../../rules/default_excludes.toml");
    assert!(
        !rules.contains("\"pdf\""),
        "rules/default_excludes.toml extensions must not list \"pdf\": the skip gate returns before \
         structured extraction, so listing pdf silently drops PDF text streams."
    );

    let extract = read("src/filesystem/extract.rs");
    assert!(
        extract.contains("mod pdf;") && extract.contains("ext == \"pdf\""),
        "filesystem/extract.rs must keep a dedicated .pdf route before generic text/binary fallback"
    );

    let pdf = read("src/filesystem/extract/pdf.rs");
    assert!(
        pdf.contains("filesystem/pdf") && pdf.contains("FlateDecode") && pdf.contains("/Encrypt"),
        "filesystem/extract/pdf.rs must own PDF provenance, compressed stream decode, and encrypted-PDF coverage gaps"
    );
}
