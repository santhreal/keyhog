//! GitHub code-scanning maps alerts to PR files by a REPO-RELATIVE
//! `artifactLocation.uri`. keyhog records absolute paths, so an absolute path
//! under the scan root (= repo root when the Action runs from the checkout)
//! must be rendered relative; before this, the SARIF emitted `file:///abs/...`
//! URIs that uploaded fine but never annotated the PR.
use keyhog_core::report::sarif_uri::relative_to;
use std::path::Path;

#[test]
fn sarif_uri_absolute_under_root_relativizes() {
    // Absolute path under the root -> repo-relative.
    assert_eq!(
        relative_to("/repo/src/leak.env", Path::new("/repo")),
        Some("src/leak.env".to_string())
    );
    assert_eq!(
        relative_to("/repo/a/b/c.txt", Path::new("/repo")),
        Some("a/b/c.txt".to_string())
    );
    // Absolute path OUTSIDE the root -> None (caller falls back to file://).
    assert_eq!(relative_to("/etc/passwd", Path::new("/repo")), None);
    // The root itself is not under a deeper root.
    assert_eq!(relative_to("/repo", Path::new("/repo/src")), None);
}
