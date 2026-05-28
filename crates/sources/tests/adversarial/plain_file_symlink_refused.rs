//! Plain-text reads must refuse symlink paths (O_NOFOLLOW / Windows guard).

use super::support::oracle_plain_file_symlink_refused;

#[test]
fn plain_file_symlink_refused() {
    oracle_plain_file_symlink_refused();
}
