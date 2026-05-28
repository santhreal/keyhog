//! Adversarial (Unix): partial read of JSON stdout must not leave child hung forever.

#[test]
fn pipe_stdout_json_valid_unix() {
    crate::adversarial::support::oracle_pipe_stdout_json_valid();
}
