//! Permission-denied entries must be skipped while the rest of the tree scans.

use super::support::oracle_permission_denied_subtree_scan_continues;

#[test]
fn permission_denied_subtree_scan_continues() {
    oracle_permission_denied_subtree_scan_continues();
}
