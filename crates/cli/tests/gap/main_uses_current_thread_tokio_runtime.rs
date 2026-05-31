//! PERF-03: plain filesystem scans must not spawn a full Tokio worker pool.

#[test]
fn main_uses_current_thread_tokio_runtime() {
    let main_rs = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
    assert!(
        main_rs.contains("#[tokio::main(flavor = \"current_thread\")]"),
        "main.rs must use Tokio's current-thread runtime; scan parallelism belongs to Rayon"
    );
    assert!(
        !main_rs.contains("#[tokio::main]\n"),
        "the default tokio::main macro creates a multi-thread runtime"
    );
}
