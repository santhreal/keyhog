//! Logic for the `detectors` subcommand.

use crate::args::DetectorArgs;
use anyhow::Result;

pub fn run(args: DetectorArgs) -> Result<()> {
    let detectors = if args.detectors.exists() && args.detectors.is_dir() {
        keyhog_core::load_detectors(&args.detectors)?
    } else {
        // Fall back to embedded detectors
        let embedded = keyhog_core::embedded_detector_tomls();
        if embedded.is_empty() {
            anyhow::bail!(
                "detector directory '{}' not found and no embedded detectors available. Fix: rebuild with detectors/ directory or specify --detectors <path>",
                args.detectors.display()
            );
        }
        let mut dets = Vec::new();
        for (name, toml_content) in embedded {
            match toml::from_str::<keyhog_core::DetectorFile>(toml_content) {
                Ok(file) => dets.push(file.detector),
                Err(e) => eprintln!("warning: failed to parse embedded detector {name}: {e}"),
            }
        }
        dets
    };
    let source = if args.detectors.exists() {
        format!("{}", args.detectors.display())
    } else {
        "embedded".to_string()
    };

    // Apply --search filter case-insensitively against the four most useful
    // fields. The 888-strong corpus is otherwise hard to navigate by eye —
    // `keyhog detectors --search aws` should beat `grep -r aws detectors/`.
    //
    // Byte-level case-insensitive substring search. The previous flow
    // allocated ~5 lowercased Strings per detector (id + name + service
    // + per-keyword) on every search; with 888 detectors that's
    // thousands of throwaway allocations per `--search`.
    fn contains_ci(haystack: &str, needle: &[u8]) -> bool {
        if needle.is_empty() || needle.len() > haystack.len() {
            return needle.is_empty();
        }
        haystack
            .as_bytes()
            .windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle))
    }
    let needle: Option<Vec<u8>> = args.search.as_ref().map(|s| s.as_bytes().to_vec());
    let filtered: Vec<&keyhog_core::DetectorSpec> = detectors
        .iter()
        .filter(|d| match needle.as_deref() {
            None => true,
            Some(q) => {
                contains_ci(&d.id, q)
                    || contains_ci(&d.name, q)
                    || contains_ci(&d.service, q)
                    || d.keywords.iter().any(|k| contains_ci(k, q))
            }
        })
        .collect();

    if let Some(q) = args.search.as_deref() {
        println!(
            "Loaded {} detectors ({source}); {} match '{q}':",
            detectors.len(),
            filtered.len()
        );
    } else {
        println!("Loaded {} detectors ({source}):", detectors.len());
    }

    if args.verbose {
        for d in &filtered {
            print_detector_verbose(d);
        }
        return Ok(());
    }

    let mut by_service: std::collections::BTreeMap<String, Vec<&str>> =
        std::collections::BTreeMap::new();
    for d in &filtered {
        by_service
            .entry(d.service.clone())
            .or_default()
            .push(d.id.as_str());
    }

    for (service, ids) in &by_service {
        println!("  - {} ({} detectors)", service, ids.len());
        for id in ids {
            println!("    - {}", id);
        }
    }

    Ok(())
}

fn print_detector_verbose(d: &keyhog_core::DetectorSpec) {
    println!();
    println!("  {}", d.id);
    println!("    name:      {}", d.name);
    println!("    service:   {}", d.service);
    println!("    severity:  {:?}", d.severity);
    if !d.keywords.is_empty() {
        println!("    keywords:  {}", d.keywords.join(", "));
    }
    for (i, p) in d.patterns.iter().enumerate() {
        let label = if d.patterns.len() > 1 {
            format!("pattern[{i}]")
        } else {
            "pattern".to_string()
        };
        println!("    {label}:   {}", p.regex);
        if let Some(desc) = &p.description {
            println!("      desc:    {desc}");
        }
        if let Some(g) = p.group {
            println!("      group:   {g}");
        }
    }
    if !d.companions.is_empty() {
        println!("    companions:");
        for c in &d.companions {
            println!(
                "      - {} (within {} lines, required={}): {}",
                c.name, c.within_lines, c.required, c.regex
            );
        }
    }
    if d.verify.is_some() {
        println!("    verify:    yes");
    }
}
