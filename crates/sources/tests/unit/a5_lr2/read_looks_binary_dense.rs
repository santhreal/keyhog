use keyhog_sources::testing::{SourceTestApi, TestApi};
#[test]
fn read_looks_binary_dense() {
    let mut b = vec![b'a'; 200]; for x in b.iter_mut().take(50) {{ *x = 0x03; }} assert!(TestApi.looks_binary(&b));
}
