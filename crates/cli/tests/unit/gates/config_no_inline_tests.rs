//! Gate `config`: no inline test BODIES (Santh folder contract).
//!
//! The contract is about where test code lives, not about the four characters
//! `#[cfg(test)]`. The sanctioned way to unit-test a private module is a
//! `#[cfg(test)] #[path = "../tests/..."] mod` hook, exactly as `lib.rs` does
//! for `docs_help_coherence`: the attribute sits in `src`, the code does not.
//! A blanket ban on the attribute forbade that pattern and pushed a test either
//! into the file it covers or out of reach of the private types it covers.

#[test]
fn config_no_inline_tests() {
    for path in [
        concat!(env!("CARGO_MANIFEST_DIR"), "/src/config.rs"),
        concat!(env!("CARGO_MANIFEST_DIR"), "/src/config/limits.rs"),
        concat!(env!("CARGO_MANIFEST_DIR"), "/src/config/schema.rs"),
    ] {
        let src = std::fs::read_to_string(path).expect("source readable");
        let lines: Vec<&str> = src.lines().map(str::trim).collect();
        for (index, line) in lines.iter().enumerate() {
            if *line != "#[cfg(test)]" {
                continue;
            }
            let next = lines
                .iter()
                .skip(index + 1)
                .find(|candidate| !candidate.is_empty())
                .copied()
                .unwrap_or_default();
            assert!(
                next.starts_with("#[path = \"../tests/"),
                "{path}:{}: move inline tests to crates/cli/tests/ and include them with \
                 `#[cfg(test)] #[path = \"../tests/...\"] mod ...;`, found {next:?}",
                index + 1
            );
        }
    }
}
