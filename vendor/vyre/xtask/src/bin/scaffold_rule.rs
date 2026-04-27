use std::fs;
use std::path::Path;

fn main() {
    let mut args = std::env::args().skip(1);
    let slug = args.next().expect("Expected rule slug");

    let launch_dir = Path::new("../../../../../rules/launch").join(&slug);
    fs::create_dir_all(&launch_dir).unwrap();

    fs::write(launch_dir.join("CONTRACT.md"), "# Rule Contract\n").unwrap();

    let test_dir = Path::new("../../../../../tests/launch_rule_truth").join(&slug);
    fs::create_dir_all(&test_dir).unwrap();

    for d in &["positives", "negatives", "evasions", "cross_file"] {
        fs::create_dir_all(test_dir.join(d)).unwrap();
    }

    fs::write(test_dir.join("cve_replay.toml"), "").unwrap();
    fs::write(test_dir.join("property.rs"), "").unwrap();
    fs::write(test_dir.join("differential.toml"), "").unwrap();
    fs::write(test_dir.join("e2e_cli.rs"), "").unwrap();

    println!("Scaffolded rule {}", slug);
}
