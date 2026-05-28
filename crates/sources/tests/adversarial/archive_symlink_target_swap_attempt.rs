//! Symlinked archive path pointing at a swapped target must stay unread.

use super::support::oracle_archive_symlink_target_swap_attempt;

#[test]
fn archive_symlink_target_swap_attempt() {
    oracle_archive_symlink_target_swap_attempt();
}
