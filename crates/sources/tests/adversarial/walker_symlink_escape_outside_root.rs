//! Directory walker must not follow symlinks that point outside the scan root.

use super::support::oracle_walker_symlink_escape_outside_root;

#[test]
fn walker_symlink_escape_outside_root() {
    oracle_walker_symlink_escape_outside_root();
}
