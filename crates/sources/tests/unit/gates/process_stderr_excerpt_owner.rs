//! Gate bounded child-process stderr excerpt ownership.

use std::path::Path;

fn source(path: impl AsRef<Path>) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

#[test]
fn process_stderr_excerpt_has_one_owner() {
    let owner = source("src/process_excerpt.rs");
    assert!(
        owner.contains("pub(crate) const STDERR_EXCERPT_BYTES: usize = 64 * 1024")
            && owner.contains("pub(crate) fn drain_stderr_excerpt(")
            && owner.contains("[stderr truncated after 65536 bytes]"),
        "src/process_excerpt.rs must own the bounded stderr excerpt primitive"
    );

    for path in ["src/git/mod.rs", "src/docker.rs", "src/hosted_git.rs"] {
        let body = source(path);
        assert!(
            body.contains("crate::process_excerpt::drain_stderr_excerpt(pipe)"),
            "{path} must route child stderr through the shared excerpt owner"
        );
        assert!(
            !body.contains("fn drain_stderr_excerpt(")
                && !body.contains("fn drain_docker_stderr_excerpt(")
                && !body.contains("fn drain_hosted_git_stderr_excerpt("),
            "{path} must not define a local stderr excerpt drain"
        );
        assert!(
            !body.contains("GIT_STDERR_EXCERPT_BYTES")
                && !body.contains("DOCKER_STDERR_EXCERPT_BYTES")
                && !body.contains("HOSTED_GIT_STDERR_EXCERPT_BYTES"),
            "{path} must not own a per-source stderr excerpt cap"
        );
    }
}
