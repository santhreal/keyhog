//! GitHub code-scanning maps alerts to PR files by a REPO-RELATIVE
//! `artifactLocation.uri`. keyhog records absolute paths, so an absolute path
//! under the scan root (= repo root when the Action runs from the checkout)
//! must be rendered relative; before this, the SARIF emitted `file:///abs/...`
//! URIs that uploaded fine but never annotated the PR.
use std::path::Path;

#[test]
fn sarif_uri_absolute_under_root_relativizes() {
    // Absolute path under the root -> repo-relative.
    assert_eq!(
        keyhog_core::testing::CoreTestApi::sarif_relative_to(
            &keyhog_core::testing::TestApi,
            "/repo/src/leak.env",
            Path::new("/repo")
        ),
        Some("src/leak.env".to_string())
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::sarif_relative_to(
            &keyhog_core::testing::TestApi,
            "/repo/a/b/c.txt",
            Path::new("/repo")
        ),
        Some("a/b/c.txt".to_string())
    );
    // Absolute path OUTSIDE the root -> None (caller falls back to file://).
    assert_eq!(
        keyhog_core::testing::CoreTestApi::sarif_relative_to(
            &keyhog_core::testing::TestApi,
            "/etc/passwd",
            Path::new("/repo")
        ),
        None
    );
    // The root itself is not under a deeper root.
    assert_eq!(
        keyhog_core::testing::CoreTestApi::sarif_relative_to(
            &keyhog_core::testing::TestApi,
            "/repo",
            Path::new("/repo/src")
        ),
        None
    );
}
