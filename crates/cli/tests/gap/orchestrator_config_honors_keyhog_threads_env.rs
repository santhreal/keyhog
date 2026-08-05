//! Contract: ambient `KEYHOG_THREADS` never changes the resolved thread count.
//!
//! Thread count comes from `--threads` / `[scan].threads` only. Driven through
//! the real binary so the guarantee is observed in `config --effective` output
//! rather than grepped out of `orchestrator_config.rs`.

use crate::support::binary;
use std::process::Command;

fn effective_threads(env: Option<(&str, &str)>, args: &[&str]) -> String {
    let mut command = Command::new(binary());
    command.arg("config").arg("--effective").args(args);
    match env {
        Some((key, value)) => {
            command.env(key, value);
        }
        None => {
            command.env_remove("KEYHOG_THREADS");
        }
    }
    let output = command.output().expect("spawn keyhog config --effective");
    assert_eq!(
        output.status.code(),
        Some(0),
        "config --effective must exit 0; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("threads = ").map(str::to_owned))
        .expect("effective config must print a `threads = ` line")
}

#[test]
fn ambient_keyhog_threads_does_not_change_the_effective_thread_count() {
    let baseline = effective_threads(None, &[]);
    let with_env = effective_threads(Some(("KEYHOG_THREADS", "99")), &[]);

    assert_eq!(
        with_env, baseline,
        "KEYHOG_THREADS must be ignored: thread count comes from --threads / [scan].threads"
    );
    assert_ne!(
        with_env, "99",
        "the ambient env value must never become the effective thread count"
    );
}

#[test]
fn explicit_threads_flag_wins_over_ambient_keyhog_threads() {
    // Proves the oracle above is not vacuous: the same output line does move
    // when the supported surface sets it.
    let explicit = effective_threads(Some(("KEYHOG_THREADS", "99")), &["--threads", "3"]);
    assert_eq!(explicit, "3");
}
