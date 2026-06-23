#[test]
fn args_detectors_surface_has_one_owner() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let args = std::fs::read_to_string(root.join("src/args.rs")).expect("args.rs readable");
    let detectors =
        std::fs::read_to_string(root.join("src/args/detectors.rs")).expect("detectors.rs readable");

    assert!(
        args.contains("mod detectors;")
            && args.contains("pub use detectors::{DetectorArgs, DetectorFormat};"),
        "args.rs must re-export detector command args from the detectors module"
    );

    for owned in ["pub struct DetectorArgs", "pub enum DetectorFormat"] {
        assert!(
            detectors.contains(owned),
            "args/detectors.rs must own `{owned}`"
        );
        assert!(
            !args.contains(owned),
            "args.rs must not re-own `{owned}` after the detectors split"
        );
    }
}
