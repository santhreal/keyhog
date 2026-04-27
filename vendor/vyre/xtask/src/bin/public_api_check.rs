use std::fs;
use std::path::Path;
use std::process::Command;

const CRATES: &[&str] = &[
    "vyre-spec",
    "vyre-foundation",
    "vyre-primitives",
    "vyre-libs",
    "vyre-driver",
    "vyre-driver-wgpu",
    "vyre-driver-spirv",
    "vyre-driver-megakernel",
    "vyre-runtime",
    "vyre-cc",
    "vyre-intrinsics",
    "vyre-reference",
    "surgec",
    "surge",
    "surge-source",
];

fn main() {
    let mut args = std::env::args().skip(1);
    let is_update = args.next().as_deref() == Some("--update");

    let mut failed = false;

    // Use cargo metadata or just hardcode paths to find crates for now.
    // In a real xtask we'd parse `cargo metadata`, but let's locate them simply.
    let root = Path::new("../../..");
    // actually, let's just run `cargo public-api -p <crate>` and compare it to `<crate_dir>/PUBLIC_API.md`.

    for crate_name in CRATES {
        let output = Command::new("cargo")
            .arg("public-api")
            .arg("-p")
            .arg(crate_name)
            .output()
            .expect("failed to execute cargo public-api");

        if !output.status.success() {
            eprintln!(
                "Failed to generate public API for {}: {}",
                crate_name,
                String::from_utf8_lossy(&output.stderr)
            );
            failed = true;
            continue;
        }

        let new_api = String::from_utf8(output.stdout).unwrap();

        let md_path = match find_crate_dir(crate_name, root) {
            Some(p) => p.join("PUBLIC_API.md"),
            None => {
                eprintln!("Could not find dir for crate {}", crate_name);
                failed = true;
                continue;
            }
        };

        if is_update {
            fs::write(&md_path, new_api).unwrap();
            println!("Updated {}", md_path.display());
        } else {
            let old_api = fs::read_to_string(&md_path).unwrap_or_default();
            if new_api != old_api {
                eprintln!("Public API drifted for crate {}! Run `cargo xtask public-api-update` to regenerate.", crate_name);
                // Also could run diff literally
                failed = true;
            } else {
                println!("{} API matches snapshot.", crate_name);
            }
        }
    }

    if failed && !is_update {
        std::process::exit(1);
    }
}

fn find_crate_dir(name: &str, root: &Path) -> Option<std::path::PathBuf> {
    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.path().components().any(|c| c.as_os_str() == "target") {
            continue;
        }
        if entry.file_name() == "Cargo.toml" {
            let content = fs::read_to_string(entry.path()).unwrap_or_default();
            if content.contains(&format!("name = \"{}\"", name)) {
                return Some(entry.path().parent().unwrap().to_path_buf());
            }
        }
    }
    None
}
