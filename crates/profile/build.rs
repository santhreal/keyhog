use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=KEYHOG_SOURCE_REVISION");
    if let Ok(revision) = std::env::var("KEYHOG_SOURCE_REVISION") {
        println!("cargo:rustc-env=KEYHOG_SOURCE_REVISION={revision}");
    }
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown-target".to_owned());
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "unknown-profile".to_owned());
    let mut features = std::env::vars()
        .filter_map(|(name, value)| {
            (name.starts_with("CARGO_FEATURE_") && value == "1").then(|| {
                name.trim_start_matches("CARGO_FEATURE_")
                    .to_ascii_lowercase()
            })
        })
        .collect::<Vec<_>>();
    features.sort_unstable();
    let compiler = std::env::var_os("RUSTC")
        .and_then(|rustc| {
            Command::new(rustc)
                .arg("--version")
                .arg("--verbose")
                .output()
                .ok()
        })
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().replace('\n', "; "))
        .unwrap_or_else(|| "unavailable".to_owned());
    println!("cargo:rustc-env=KEYHOG_PROFILE_BUILD_TARGET={target}");
    println!("cargo:rustc-env=KEYHOG_PROFILE_BUILD_PROFILE={profile}");
    println!(
        "cargo:rustc-env=KEYHOG_PROFILE_BUILD_FEATURES={}",
        features.join(",")
    );
    println!("cargo:rustc-env=KEYHOG_PROFILE_RUSTC={compiler}");
}
