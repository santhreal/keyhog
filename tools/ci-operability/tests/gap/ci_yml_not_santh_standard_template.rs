//! KH-GAP-130: STANDARD CI contract (repo `.github/workflows/ci.yml` is the 5-line santh-ci reuse).

use super::support::spec_waiver::spec_waiver_active;
use super::support::{repo_root, CI_YML_WAIVER as WAIVER_REL};

#[test]
fn ci_yml_uses_santh_ci_shared_workflow_template() {
    if spec_waiver_active(WAIVER_REL) {
        let waiver = std::fs::read_to_string(repo_root().join(WAIVER_REL)).expect("waiver");
        assert!(
            waiver.contains("LFS") && waiver.contains("14") && waiver.contains("fuzz"),
            "active waiver must document LFS, 14-runner, and fuzz extensions"
        );
        return;
    }
    let path = repo_root().join(".github/workflows/ci.yml");
    let lines: Vec<_> = std::fs::read_to_string(&path)
        .expect("ci.yml")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect();
    assert!(
        lines.len() <= 6,
        "STANDARD.md CI contract expects ~5-line ci.yml; got {} non-comment lines",
        lines.len()
    );
    let joined = lines.join("\n");
    assert!(
        joined.contains("santh-project/santh-ci/.github/workflows/main.yml"),
        "ci.yml must `uses:` shared santh-ci workflow per STANDARD.md"
    );
}
