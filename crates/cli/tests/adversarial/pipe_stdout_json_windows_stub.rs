//! Windows oracle: piped JSON stdout must complete and parse (all targets).

#[test]
fn pipe_stdout_json_windows_stub() {
    crate::support::oracle_pipe_stdout_json_valid();
}
