//! CI dependency contract for the fail-closed Marketplace verifier gates.

use super::support::read_workflow;

/// The clean hosted audit job has no ambient PyYAML. It must install the exact
/// hashed parser lock before `run_all.sh`, or every verifier test fails before
/// reaching the behavior it is meant to prove.
#[test]
fn prevention_gate_installs_pinned_marketplace_parser_before_running() {
    let workflow = read_workflow("ci.yml");
    let audit = workflow
        .split("  audit-gates:")
        .nth(1)
        .expect("CI must define audit-gates")
        .split("\n  strict-runners:")
        .next()
        .expect("audit-gates must end before strict-runners");
    let setup = audit
        .find("uses: actions/setup-python@")
        .expect("audit-gates must install a pinned Python runtime");
    let install = audit
        .find("name: Install prevention gate Python dependencies")
        .expect("audit-gates must install Marketplace verifier dependencies");
    let gates = audit
        .find("name: Run all prevention gates")
        .expect("audit-gates must run the prevention entrypoint");
    assert!(
        setup < install && install < gates,
        "the pinned parser must exist before prevention tests import the verifier"
    );
    assert!(
        audit.contains("python-version: '3.12.11'")
            && audit.contains("--disable-pip-version-check --no-deps")
            && audit.contains("--require-hashes --only-binary=:all:")
            && audit.contains("-r scripts/requirements-marketplace.txt")
            && audit.contains("yaml.__version__ == \"6.0.3\""),
        "audit-gates must install and attest the exact hashed PyYAML parser lock"
    );
}
