use keyhog::testing::{CliTestApi as _, API};

#[test]
fn sanitise_thread_count_passes_sane_values() {
    assert_eq!(API.sanitise_thread_count(4, 8, "test"), 4);
}
