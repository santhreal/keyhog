use keyhog::testing::{CliTestApi as _, API};

#[test]
fn sanitise_thread_count_caps_pathological() {
    assert_eq!(API.sanitise_thread_count(999_999, 8, "test"), 256);
}
