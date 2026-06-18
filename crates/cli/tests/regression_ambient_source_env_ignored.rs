//! Ambient env must never select scan targets.

use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::testing::{CliTestApi as _, API};
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

const AMBIENT_SOURCE_ENV: &[(&str, &str)] = &[
    ("SLACK_TOKEN", "xoxb-redacted"),
    ("S3_BUCKET", "secret-bucket"),
    ("GCS_BUCKET", "secret-gcs-bucket"),
    (
        "AZURE_BLOB_CONTAINER_URL",
        "https://acct.blob.core.windows.net/container?sig=redacted",
    ),
];

struct RestoreEnv(Vec<(&'static str, Option<String>)>);

impl Drop for RestoreEnv {
    fn drop(&mut self) {
        for (name, value) in &self.0 {
            // SAFETY: this test serializes its own mutations and restores the
            // process env before returning.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}

fn with_ambient_source_env<R>(body: impl FnOnce() -> R) -> R {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let saved = AMBIENT_SOURCE_ENV
        .iter()
        .map(|(name, _)| (*name, std::env::var(name).ok()))
        .collect();
    let _restore = RestoreEnv(saved);

    for (name, value) in AMBIENT_SOURCE_ENV {
        // SAFETY: guarded above; restored by RestoreEnv.
        unsafe {
            std::env::set_var(name, value);
        }
    }

    body()
}

#[test]
fn build_sources_ignores_ambient_remote_source_env() {
    with_ambient_source_env(|| {
        let args = ScanArgs::try_parse_from(["scan"]).expect("parse default scan args");
        let sources = API
            .build_sources(&args, vec![], None)
            .expect("build sources");

        assert!(
            sources.is_empty(),
            "ambient source env must not create scan targets; got {:?}",
            sources
                .iter()
                .map(|source| source.name())
                .collect::<Vec<_>>()
        );
    });
}

#[test]
fn source_factory_has_no_dead_global_registry_fallback() {
    let src = include_str!("../src/sources.rs");
    assert!(
        !src.contains("keyhog_core::get_source"),
        "source construction must not fall back to the dead global registry branch"
    );
    assert!(
        !src.contains("register the source plugin before using --source"),
        "operator errors must not advertise a registry plugin path the binary cannot wire"
    );
}
