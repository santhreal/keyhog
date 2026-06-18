use keyhog::testing::{CliTestApi as _, API};

#[test]
fn sanitise_thread_count_zero_fallback() {
    assert_eq!(API.sanitise_thread_count(0, 8, "test"), 8);
}
