use crate::args::ScanArgs;
use anyhow::Result;
use keyhog_core::{load_detectors, DetectorSpec};
use keyhog_scanner::ScannerConfig;
use std::path::{Path, PathBuf};

pub(crate) fn configure_threads(threads: Option<usize>, physical_cores: usize) {
    // Resolution order: --threads CLI arg > KEYHOG_THREADS env > physical core
    // count. Physical (not logical) is the right default for CPU-bound regex
    // — SMT/Hyperthreading siblings share execution units, so 2× the threads
    // yields ~1.1× the throughput while doubling cache pressure.
    let (n, source) = if let Some(t) = threads {
        (t, "cli-arg")
    } else if let Ok(env) = std::env::var("KEYHOG_THREADS") {
        match env.parse::<usize>() {
            Ok(t) if t > 0 => (t, "env:KEYHOG_THREADS"),
            _ => {
                tracing::warn!(value = %env, "ignoring invalid KEYHOG_THREADS value");
                (physical_cores, "physical-cores")
            }
        }
    } else {
        (physical_cores, "physical-cores")
    };

    let builder = rayon::ThreadPoolBuilder::new()
        .num_threads(n)
        .stack_size(8 * 1024 * 1024)
        // Cross-OS thread name so external profilers (perf, dtrace,
        // Activity Monitor, htop) can group keyhog workers separately
        // from the calling process. Previously macOS-only.
        .thread_name(|i| format!("keyhog-worker-{i}"));

    if let Err(error) = builder.build_global() {
        tracing::warn!(
            requested_threads = n,
            source,
            "failed to configure rayon thread pool: {error}"
        );
    } else {
        tracing::info!(
            threads = n,
            source,
            physical_cores,
            "rayon thread pool configured"
        );
    }
}

pub(crate) fn auto_discover_detectors(path: &Path) -> Result<PathBuf> {
    if let Ok(env_path) = std::env::var("KEYHOG_DETECTORS") {
        let p = PathBuf::from(&env_path);
        if p.exists() && p.is_dir() {
            return Ok(p);
        }
    }

    if path == Path::new("detectors") && !path.exists() {
        let default_dirs = [
            dirs::home_dir().map(|h| h.join(".keyhog/detectors")),
            Some(PathBuf::from("/usr/share/keyhog/detectors")),
            Some(PathBuf::from("/usr/local/share/keyhog/detectors")),
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.join("detectors"))),
        ];
        for dir in default_dirs.into_iter().flatten() {
            if dir.exists() && dir.is_dir() {
                eprintln!("Auto-detected: using detectors directory {}", dir.display());
                return Ok(dir);
            }
        }
    }
    Ok(path.to_path_buf())
}

pub(crate) fn load_detectors_with_cache(path: &Path) -> Result<Vec<DetectorSpec>> {
    if path.exists() && path.is_dir() {
        let cache_path = path.join(".keyhog-cache.json");
        if let Some(cached) = keyhog_core::load_detector_cache(&cache_path, path) {
            return Ok(cached);
        }
        let loaded = load_detectors(path)?;
        let _ = keyhog_core::save_detector_cache(&loaded, &cache_path);
        return Ok(loaded);
    }
    load_detectors_embedded_or_fail(path)
}

/// Load detectors without writing or reading the on-disk
/// `.keyhog-cache.json`. Used by `--lockdown` to avoid touching disk.
/// Falls through to the embedded TOML corpus when no detectors dir
/// exists, matching `load_detectors_with_cache`'s behaviour.
pub(crate) fn load_detectors_no_cache(path: &Path) -> Result<Vec<DetectorSpec>> {
    if path.exists() && path.is_dir() {
        return load_detectors(path).map_err(anyhow::Error::from);
    }
    load_detectors_embedded_or_fail(path)
}

fn load_detectors_embedded_or_fail(path: &Path) -> Result<Vec<DetectorSpec>> {
    let embedded = keyhog_core::embedded_detector_tomls();
    if !embedded.is_empty() {
        eprintln!(
            "Using {} embedded detectors (no external detectors directory found)",
            embedded.len()
        );
        let mut detectors = Vec::new();
        for (name, toml_content) in embedded {
            match toml::from_str::<keyhog_core::DetectorFile>(toml_content) {
                Ok(file) => detectors.push(file.detector),
                Err(error) => {
                    tracing::debug!("failed to parse embedded detector {}: {}", name, error)
                }
            }
        }
        if detectors.is_empty() {
            anyhow::bail!("no detectors loaded from embedded data");
        }
        return Ok(detectors);
    }

    anyhow::bail!(
        "detectors directory '{}' not found and no embedded detectors available. \
         Fix: specify --detectors <path> or set KEYHOG_DETECTORS env var",
        path.display()
    )
}

pub(crate) fn build_scanner_config(args: &ScanArgs) -> ScannerConfig {
    let mut config = if args.fast {
        ScannerConfig::fast()
    } else if args.deep {
        ScannerConfig::thorough()
    } else {
        ScannerConfig::default()
    };

    if args.fast || args.deep {
        return config;
    }

    if let Some(depth) = args.decode_depth {
        config.max_decode_depth = depth;
    }
    if let Some(size) = args.decode_size_limit {
        config.max_decode_bytes = size;
    }
    if let Some(conf) = args.min_confidence {
        config.min_confidence = conf;
    }

    config.entropy_enabled = !args.no_entropy;
    if let Some(threshold) = args.entropy_threshold {
        config.entropy_threshold = threshold;
    }
    config.entropy_in_source_files = args.entropy_source_files;
    config.ml_enabled = !args.no_ml;
    if let Some(weight) = args.ml_weight {
        config.ml_weight = weight;
    }
    config.unicode_normalization = !args.no_unicode_norm;
    if !args.known_prefixes.is_empty() {
        config.known_prefixes = args.known_prefixes.clone();
    }
    if !args.secret_keywords.is_empty() {
        config.secret_keywords = args.secret_keywords.clone();
    }
    if !args.test_keywords.is_empty() {
        config.test_keywords = args.test_keywords.clone();
    }
    if !args.placeholder_keywords.is_empty() {
        config.placeholder_keywords = args.placeholder_keywords.clone();
    }
    config
}
