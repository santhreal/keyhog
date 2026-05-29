//! Real Linux kernel `scripts/` corpus pass-rate measurement on tip.
//!
//! Walks `tests/corpus/r2_kernel_scripts/` and runs the full
//! `parse_translation_unit` pipeline on each `.c` file. Reports pass/fail
//! per file and prints a markdown summary table to stdout.
//!
//! Marked `#[ignore]` because it is an on-demand corpus/performance gate.
//! The harness passes explicit fixture and system include roots; it must not
//! shell out to gcc/clang to discover host defaults. Run on demand:
//!
//! ```sh
//! cargo test -p vyre-frontend-c --test r2_corpus_measurement \
//!     -- --ignored --nocapture
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant, SystemTime};

/// Per-file timeout. Bumped to 900s after the v2 corpus run showed
/// sign-file.c historically completes at ~565s (heavy openssl chain).
/// 900s lets sign-file pass while still bounding genuine GPU hangs.
///
/// Each file runs in a SEPARATE child process (fork of this test
/// binary, gated by the `R2_CORPUS_SINGLE_FILE` env var) so a hang
/// inside one file does not leak its GPU work to the next file. On
/// timeout the child is killed, which tears down its CUDA context
/// cleanly and frees the GPU for the next file. This avoids the
/// cascade where a single hang false-failed every subsequent file.
const PER_FILE_TIMEOUT: Duration = Duration::from_secs(900);
const POLL_SPIN_LIMIT: u32 = 16;
const POLL_SLEEP_MAX: Duration = Duration::from_millis(10);
const SINGLE_FILE_ENV: &str = "R2_CORPUS_SINGLE_FILE";

fn chrono_like_now() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("epoch {now}s")
}

use vyre_driver_cuda as _;
use vyre_driver_wgpu as _;
use vyre_frontend_c::api::{parse_translation_unit, VyreCompileOptions};

const CORPUS_ROOT: &str = "tests/corpus/r2_kernel_scripts";
/// Skip system-include headers  -  empty after the runtime-BufLen kernel
/// refactor + gnu_attribute pre-check removal made libc-bearing TUs
/// parseable. Every file gets attempted; failures are real parser
/// feature gaps or include-path issues.
const SKIP_SYSTEM_INCLUDE_HEADERS: &[&str] = &[];

/// Skip local-sibling-include headers  -  also empty for the same reason.
const SKIP_LOCAL_INCLUDE_HEADERS: &[&str] = &[];

/// Build the include-dir search path the corpus test passes to
/// `parse_translation_unit`. Standard /usr/include for system headers,
/// plus every host-installed `linux-hwe-*-headers-*/scripts/` and
/// `linux-headers-*/scripts/` subtree so the kernel-scripts sibling
/// headers (`list.h`, `dialog.h`, `gendwarfksyms.h`, `xalloc.h`,
/// `images.h`, `mnconf-common.h`) resolve without needing the corpus
/// to vendor them. Each known sibling-header location is added.
fn discover_kernel_scripts_include_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![
        PathBuf::from("/usr/include"),
        PathBuf::from("/usr/include/x86_64-linux-gnu"),
        // GTK-3 chain (kconfig/gconf.c uses gtk/gtk.h).
        PathBuf::from("/usr/include/gtk-3.0"),
        PathBuf::from("/usr/include/glib-2.0"),
        PathBuf::from("/usr/lib/x86_64-linux-gnu/glib-2.0/include"),
        PathBuf::from("/usr/include/pango-1.0"),
        PathBuf::from("/usr/include/harfbuzz"),
        PathBuf::from("/usr/include/freetype2"),
        PathBuf::from("/usr/include/cairo"),
        PathBuf::from("/usr/include/gdk-pixbuf-2.0"),
        PathBuf::from("/usr/include/atk-1.0"),
    ];
    append_compiler_builtin_include_dirs(&mut dirs);
    let scripts_subdirs = &[
        // Top-level kernel `include/` gives us linux/build-salt.h,
        // linux/kconfig.h, linux/kbuild.h, linux/list.h, linux/asn1_*.h.
        "include",
        "include/uapi",
        // Kernel tools/include for tools/be_byteshift.h etc.
        "tools/include",
        "tools/include/uapi",
        // scripts/ root itself so e.g. `#include "recordmcount.h"`
        // from scripts/recordmcount.c resolves.
        "scripts",
        "scripts/include",
        "scripts/kconfig",
        "scripts/kconfig/lxdialog",
        "scripts/gendwarfksyms",
        "scripts/mod",
        "scripts/basic",
        "scripts/ipe/polgen",
        "scripts/selinux/mdp",
    ];
    let kernel_root_globs = &[
        "/usr/src/linux-hwe-6.17-headers-6.17.0-19",
        "/usr/src/linux-hwe-6.17-headers-6.17.0-20",
        "/usr/src/linux-hwe-6.17-headers-6.17.0-14",
        "/usr/src/linux-headers-6.17.0-14-generic",
        "/usr/src/linux-headers-6.17.0-19-generic",
        "/usr/src/linux-headers-6.17.0-20-generic",
    ];
    for root in kernel_root_globs {
        let root_path = Path::new(root);
        if !root_path.exists() {
            continue;
        }
        for sub in scripts_subdirs {
            let candidate = root_path.join(sub);
            if candidate.exists() {
                dirs.push(candidate);
            }
        }
    }
    // Vendored stub headers (be_byteshift.h, classmap.h, …) for files
    // whose source-of-truth headers ship only in the kernel-source
    // package (linux-source-6.17), not the linux-headers package the
    // CI runner has installed. Stubs live under
    // tests/corpus/r2_kernel_scripts/vendor-headers/{tools,selinux}.
    let vendor_root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/r2_kernel_scripts/vendor-headers");
    if vendor_root.exists() {
        dirs.push(vendor_root.clone());
        // selinux/ subdir gets its own entry so `#include "classmap.h"`
        // (used as a local-style include from scripts/selinux/mdp/mdp.c)
        // resolves against vendor-headers/selinux/classmap.h.
        dirs.push(vendor_root.join("selinux"));
    }
    dirs
}

fn append_compiler_builtin_include_dirs(dirs: &mut Vec<PathBuf>) {
    append_gcc_builtin_include_dirs(dirs, Path::new("/usr/lib/gcc"));
    append_clang_builtin_include_dirs(dirs, Path::new("/usr/lib"));
}

fn push_existing_include_dir(dirs: &mut Vec<PathBuf>, candidate: PathBuf) {
    if candidate.exists() && !dirs.iter().any(|dir| dir == &candidate) {
        dirs.push(candidate);
    }
}

fn append_gcc_builtin_include_dirs(dirs: &mut Vec<PathBuf>, gcc_root: &Path) {
    let Ok(targets) = std::fs::read_dir(gcc_root) else {
        return;
    };
    for target in targets.flatten() {
        let target_path = target.path();
        let Ok(versions) = std::fs::read_dir(&target_path) else {
            continue;
        };
        for version in versions.flatten() {
            let include_dir = version.path().join("include");
            if include_dir.join("stdarg.h").exists() {
                push_existing_include_dir(dirs, include_dir);
            }
        }
    }
}

fn append_clang_builtin_include_dirs(dirs: &mut Vec<PathBuf>, lib_root: &Path) {
    let Ok(entries) = std::fs::read_dir(lib_root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.starts_with("llvm-") {
            continue;
        }
        let clang_root = path.join("lib/clang");
        let Ok(versions) = std::fs::read_dir(clang_root) else {
            continue;
        };
        for version in versions.flatten() {
            let include_dir = version.path().join("include");
            if include_dir.join("stdarg.h").exists() {
                push_existing_include_dir(dirs, include_dir);
            }
        }
    }
}

fn kernel_scripts_compile_options() -> VyreCompileOptions {
    let include_dirs = discover_kernel_scripts_include_dirs();
    VyreCompileOptions {
        include_dirs: include_dirs.clone(),
        system_include_dirs: include_dirs,
        disable_system_include_dirs: true,
        ..Default::default()
    }
}

fn collect_corpus(root: &Path) -> Vec<PathBuf> {
    let mut out: Vec<(u64, PathBuf)> = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) == Some("c") {
                let size = std::fs::metadata(&path)
                    .map(|m| m.len())
                    .unwrap_or(u64::MAX);
                out.push((size, path));
            }
        }
    }
    // Sort smallest-first so the per-file progress trace exhibits the
    // pipeline behaviour on simple TUs early; large kernel-script TUs
    // (asn1_compiler, etc.) come last and self-cap via SIZE_LIMIT_BYTES.
    out.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    out.into_iter().map(|(_, path)| path).collect()
}

fn classify_error(message: &str) -> String {
    let lower = message.to_ascii_lowercase();
    if lower.contains("per-file timeout") {
        return "per-file timeout (GPU hang or absurd cold compile)".to_string();
    }
    if let Some(rest) = lower.find("system #include <") {
        let tail = &message[rest..];
        if let Some(end) = tail.find('>') {
            return format!(
                "missing system include <{}>",
                &tail[("system #include <".len())..end]
            );
        }
    }
    if lower.contains("not found (tried tu dir") {
        return "missing local include (tried tu dir + -I)".to_string();
    }
    if let Some(start) = lower.find("include `") {
        let tail = &message[start + "include `".len()..];
        if let Some(end) = tail.find('`') {
            let header = &tail[..end];
            return format!("missing include `{header}`");
        }
    }
    if lower.contains("system #include") {
        return "missing system include (other)".to_string();
    }
    if lower.contains("preprocessor") {
        return "preprocessor error".to_string();
    }
    if lower.contains("lex") || lower.contains("token") {
        return "lex / tokenization error".to_string();
    }
    if lower.contains("parse") || lower.contains("ast") {
        return "parse / AST error".to_string();
    }
    if lower.contains("sema") || lower.contains("semantic") {
        return "semantic-stage error".to_string();
    }
    if lower.contains("dispatch") || lower.contains("backend") {
        return "dispatch / backend error".to_string();
    }
    "uncategorized".to_string()
}

/// Run one file in a fresh child process and wait for it with a
/// timeout. Killing the child on timeout tears down its CUDA context
/// cleanly  -  no leaked GPU work to cascade into the next file.
fn run_file_in_subprocess(file: &Path, timeout: Duration) -> Result<(), String> {
    let exe = std::env::current_exe()
        .map_err(|error| format!("vyre-frontend-c r2 corpus: current_exe failed: {error}"))?;
    let mut child = std::process::Command::new(&exe)
        .args([
            "--ignored",
            "--exact",
            "--nocapture",
            "r2_kernel_scripts_pass_rate",
        ])
        .env(SINGLE_FILE_ENV, file)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("vyre-frontend-c r2 corpus: spawn worker failed: {error}"))?;

    let started = Instant::now();
    let pid = child.id();
    let mut empty_polls = 0u32;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = String::new();
                if let Some(mut s) = child.stdout.take() {
                    use std::io::Read as _;
                    let _ = s.read_to_string(&mut stdout);
                }
                let mut stderr = String::new();
                if let Some(mut s) = child.stderr.take() {
                    use std::io::Read as _;
                    let _ = s.read_to_string(&mut stderr);
                }
                if status.success() {
                    return Ok(());
                }
                if let Some(idx) = stdout.find("RESULT_ERR ") {
                    let msg = &stdout[idx + "RESULT_ERR ".len()..];
                    let line_end = msg.find('\n').unwrap_or(msg.len());
                    return Err(msg[..line_end].to_string());
                }
                let exit_code = status.code().unwrap_or(-1);
                return Err(format!(
                    "worker exited with status {exit_code}; stderr tail: {}",
                    stderr.lines().rev().take(3).collect::<Vec<_>>().join(" | ")
                ));
            }
            Ok(None) => {
                let elapsed = started.elapsed();
                if elapsed >= timeout {
                    let kill_status = child
                        .kill()
                        .map_or_else(|error| format!(" kill failed: {error}."), |_| String::new());
                    let wait_status = child
                        .wait()
                        .map_or_else(|error| format!(" wait failed: {error}."), |_| String::new());
                    return Err(format!(
                        "per-file timeout after {}s (worker pid {pid} killed)  -  likely GPU kernel fixpoint or PTX compile loop.{kill_status}{wait_status}",
                        timeout.as_secs(),
                    ));
                }
                empty_polls = empty_polls.saturating_add(1);
                if empty_polls <= POLL_SPIN_LIMIT {
                    std::thread::yield_now();
                    continue;
                }
                let remaining = timeout.saturating_sub(elapsed);
                std::thread::sleep(remaining.min(POLL_SLEEP_MAX));
            }
            Err(error) => {
                return Err(format!(
                    "vyre-frontend-c r2 corpus: try_wait failed for pid {pid}: {error}"
                ));
            }
        }
    }
}

/// Single-file worker mode: the corpus driver re-execs this very test
/// binary with `R2_CORPUS_SINGLE_FILE=<path>` set so each file runs in
/// its own CUDA context. Prints `RESULT_OK` or `RESULT_ERR <message>`
/// to stdout and exits.
fn run_single_file_and_exit(file: &Path) -> ! {
    let options = kernel_scripts_compile_options();
    match parse_translation_unit(file, &options) {
        Ok(_) => {
            println!("RESULT_OK");
            std::process::exit(0);
        }
        Err(message) => {
            // Single line, escape newlines so the parent can grep it cleanly.
            let escaped = message.replace('\n', " | ");
            println!("RESULT_ERR {escaped}");
            std::process::exit(1);
        }
    }
}

#[test]
#[ignore = "real-corpus measurement; uses explicit fixture/system include roots"]
fn r2_kernel_scripts_pass_rate() {
    // Single-file worker mode: parse one file and exit. The driver path
    // re-execs us with this env var set so each file gets its own
    // process / CUDA context.
    if let Ok(single) = std::env::var(SINGLE_FILE_ENV) {
        let path = PathBuf::from(single);
        run_single_file_and_exit(&path);
    }

    let corpus_root = Path::new(env!("CARGO_MANIFEST_DIR")).join(CORPUS_ROOT);
    let files = collect_corpus(&corpus_root);
    assert_ne!(files.len(), 0,
        "Fix: Linux kernel scripts/ corpus must contain at least one .c file under {}",
        corpus_root.display()
    );

    let _options = kernel_scripts_compile_options();

    let mut passes = 0usize;
    let mut fails: Vec<(PathBuf, String)> = Vec::new();
    let mut skipped: Vec<(PathBuf, u64)> = Vec::new();
    let started = Instant::now();

    for (idx, file) in files.iter().enumerate() {
        let metadata = match std::fs::metadata(file) {
            Ok(m) => m,
            Err(e) => {
                fails.push((file.clone(), format!("stat: {e}")));
                continue;
            }
        };
        if let Ok(source) = std::fs::read_to_string(file) {
            if let Some(header) = SKIP_SYSTEM_INCLUDE_HEADERS
                .iter()
                .find(|h| source.contains(&format!("#include <{h}>")))
            {
                skipped.push((file.clone(), metadata.len()));
                eprintln!(
                    "[{}/{}] SKIP {} (#include <{}> in pipeline-cost-cap list)",
                    idx + 1,
                    files.len(),
                    file.strip_prefix(&corpus_root).unwrap_or(file).display(),
                    header
                );
                continue;
            }
            if let Some(header) = SKIP_LOCAL_INCLUDE_HEADERS
                .iter()
                .find(|h| source.contains(&format!("#include \"{h}\"")))
            {
                skipped.push((file.clone(), metadata.len()));
                eprintln!(
                    "[{}/{}] SKIP {} (#include \"{}\" in pipeline-cost-cap list)",
                    idx + 1,
                    files.len(),
                    file.strip_prefix(&corpus_root).unwrap_or(file).display(),
                    header
                );
                continue;
            }
        }
        let file_started = Instant::now();
        let outcome = run_file_in_subprocess(file, PER_FILE_TIMEOUT);
        let elapsed = file_started.elapsed().as_millis();
        match outcome {
            Ok(_) => {
                passes += 1;
                eprintln!(
                    "[{}/{}] OK   {} ({} ms)",
                    idx + 1,
                    files.len(),
                    file.strip_prefix(&corpus_root).unwrap_or(file).display(),
                    elapsed
                );
            }
            Err(message) => {
                let cluster = classify_error(&message);
                eprintln!(
                    "[{}/{}] FAIL {} ({} ms) [{}]",
                    idx + 1,
                    files.len(),
                    file.strip_prefix(&corpus_root).unwrap_or(file).display(),
                    elapsed,
                    cluster
                );
                fails.push((file.clone(), message));
            }
        }
    }

    let total_attempted = files.len() - skipped.len();
    let mut clusters: BTreeMap<String, (usize, PathBuf)> = BTreeMap::new();
    for (path, message) in &fails {
        let key = classify_error(message);
        let entry = clusters
            .entry(key)
            .or_insert_with(|| (0usize, path.clone()));
        entry.0 += 1;
    }

    let elapsed = started.elapsed();

    // Also write the report to a known path so we recover it even if
    // the test runner truncates stdout or the harness times out mid-loop.
    let report_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(CORPUS_ROOT)
        .join("REPORT_TIP.md");
    let mut report = String::new();
    use std::fmt::Write as _;
    let _ = writeln!(
        report,
        "# r2_kernel_scripts_pass_rate (vyre-frontend-c on tip, {})",
        chrono_like_now()
    );
    let _ = writeln!(report, "\n- corpus root: {}", corpus_root.display());
    let _ = writeln!(report, "- total files: {}", files.len());
    let _ = writeln!(
        report,
        "- skipped by explicit header exemption: {}",
        skipped.len()
    );
    let _ = writeln!(report, "- attempted: {total_attempted}");
    let _ = writeln!(report, "- passed: {passes}");
    let _ = writeln!(report, "- failed: {}", fails.len());
    let _ = writeln!(report, "- elapsed: {:.2}s", elapsed.as_secs_f64());
    if !clusters.is_empty() {
        let _ = writeln!(report, "\n## Failure clusters\n\n| Count | Cluster |");
        let _ = writeln!(report, "|-------|---------|");
        for (cluster, (count, _)) in &clusters {
            let _ = writeln!(report, "| {count} | {cluster} |");
        }
    }
    if let Err(e) = std::fs::write(&report_path, &report) {
        eprintln!("warning: could not write {}: {e}", report_path.display());
    } else {
        eprintln!("report written: {}", report_path.display());
    }

    println!();
    println!("# r2_kernel_scripts_pass_rate (vyre-frontend-c on tip)");
    println!();
    println!("- corpus root: {}", corpus_root.display());
    println!("- total files: {}", files.len());
    println!("- skipped by explicit header exemption: {}", skipped.len());
    println!("- attempted: {total_attempted}");
    println!("- passed: {passes}");
    println!("- failed: {}", fails.len());
    println!("- elapsed: {:.2}s", elapsed.as_secs_f64());
    println!();

    if !skipped.is_empty() {
        println!("## SKIPPED (explicit header exemption)");
        println!();
        println!("| File | Size |");
        println!("|------|------|");
        for (path, size) in &skipped {
            let rel = path.strip_prefix(&corpus_root).unwrap_or(path).display();
            println!("| `{rel}` | {size} bytes |");
        }
        println!();
    }

    if !clusters.is_empty() {
        println!("## Failure clusters");
        println!();
        println!("| Count | Cluster | Example file |");
        println!("|-------|---------|--------------|");
        for (cluster, (count, example)) in &clusters {
            let rel = example
                .strip_prefix(&corpus_root)
                .unwrap_or(example)
                .display();
            println!("| {count} | {cluster} | `{rel}` |");
        }
        println!();
    }

    if passes > 0 {
        println!("## Passing files");
        println!();
        for file in &files {
            if !fails.iter().any(|(p, _)| p == file) {
                let rel = file.strip_prefix(&corpus_root).unwrap_or(file).display();
                println!("- `{rel}`");
            }
        }
        println!();
    }

    println!("## All failures (first 1KB of each error)");
    println!();
    for (path, message) in &fails {
        let rel = path.strip_prefix(&corpus_root).unwrap_or(path).display();
        let truncated = if message.len() > 1024 {
            &message[..1024]
        } else {
            message.as_str()
        };
        println!("### `{rel}`");
        println!();
        println!("```");
        println!("{truncated}");
        println!("```");
        println!();
    }

    if passes == 0 {
        panic!(
            "vyre-frontend-c parsed 0 of {total_attempted} attempted Linux kernel scripts/ files. \
             Fix: investigate the most common failure cluster above and re-wire the parser path that's missing."
        );
    }
}

#[test]
#[ignore = "throughput measurement on synthetic safe corpus"]

fn r2_synthetic_throughput_files_per_ms() {
    use vyre_frontend_c::api::parse_syntax_batch_bytes;

    // Generate a corpus of small, fast-path-safe synthetic C source files.
    // Each file is ~2 KB  -  closer to the kernel-scripts average (~10 KB)
    // while staying inside the 8 MB batch ceiling at 4096 files.
    let mut sources: Vec<Vec<u8>> = Vec::new();
    let n_files: usize = std::env::var("THROUGHPUT_N_FILES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8192);
    let n_funcs_per_file: usize = std::env::var("THROUGHPUT_N_FUNCS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
    for i in 0..n_files {
        let mut s = String::with_capacity(n_funcs_per_file * 80);
        for j in 0..n_funcs_per_file {
            s.push_str(&format!(
                "int func_{i}_{j}(int a, int b) {{ return (a + b) * {j} + {i}; }}\n"
            ));
        }
        s.push_str(&format!(
            "int helper_{i}(void) {{ return func_{i}_0(1, 2); }}\n"
        ));
        sources.push(s.into_bytes());
    }
    let total_bytes: u64 = sources.iter().map(|s| s.len() as u64).sum();
    eprintln!(
        "[throughput] generated {} files ({:.2} KB) at {}",
        sources.len(),
        total_bytes as f64 / 1024.0,
        chrono_like_now(),
    );

    // Warm pipeline cache.
    if let Some(first) = sources.first() {
        let warm = parse_syntax_batch_bytes(&[first.as_slice()]);
        eprintln!(
            "[throughput] warmup parse: {}",
            warm.as_ref()
                .map(|s| format!("{} files, {} tokens", s.file_count, s.token_count))
                .unwrap_or_else(|e| format!("FAIL {e}"))
        );
    }
    // Second warmup with full batch shape  -  first dispatch on this batch
    // size pays the per-shape cold compile.
    let refs: Vec<&[u8]> = sources.iter().map(Vec::as_slice).collect();
    let warm2 = parse_syntax_batch_bytes(&refs);
    eprintln!(
        "[throughput] full-batch warmup: {}",
        warm2
            .as_ref()
            .map(|s| format!("{} files, {} tokens", s.file_count, s.token_count))
            .unwrap_or_else(|e| format!("FAIL {e}"))
    );

    let started = Instant::now();
    let summary = parse_syntax_batch_bytes(&refs).expect("batch parse must succeed");
    let elapsed = started.elapsed();

    let elapsed_ms = elapsed.as_secs_f64() * 1000.0;
    let files_per_ms = sources.len() as f64 / elapsed_ms.max(1e-9);
    let mb_per_sec = total_bytes as f64 / 1024.0 / 1024.0 / elapsed.as_secs_f64().max(1e-9);

    eprintln!("");
    eprintln!("[throughput] === RESULTS ===");
    eprintln!("[throughput] backend:        {}", summary.backend_id);
    eprintln!("[throughput] files:          {}", summary.file_count);
    eprintln!("[throughput] source bytes:   {}", summary.source_bytes);
    eprintln!("[throughput] tokens:         {}", summary.token_count);
    eprintln!("[throughput] ast nodes:      {}", summary.ast_node_count);
    eprintln!("[throughput] elapsed:        {:.3} ms", elapsed_ms);
    eprintln!("[throughput] files/ms:       {:.2}", files_per_ms);
    eprintln!("[throughput] MB/s:           {:.2}", mb_per_sec);
    eprintln!(
        "[throughput] target:         100 files/ms (currently {:.2}x of target)",
        files_per_ms / 100.0
    );
}

#[test]
#[ignore = "single-file timing for parse_translation_unit warm/cold profile"]
fn r2_single_file_warm_cold_timing() {
    let target = std::env::var("R2_TIMING_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(CORPUS_ROOT)
                .join("mod/empty.c")
        });
    eprintln!("[timing] target: {}", target.display());
    let warmups: usize = std::env::var("R2_TIMING_WARMUPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);
    let trials: usize = std::env::var("R2_TIMING_TRIALS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
    let options = kernel_scripts_compile_options();
    for w in 0..warmups {
        let t = Instant::now();
        let r = parse_translation_unit(&target, &options);
        eprintln!(
            "[timing] warmup {w}: {} ms  -  {}",
            t.elapsed().as_millis(),
            r.map(|_| "ok".to_string())
                .unwrap_or_else(|e| format!("ERR {}", &e[..e.len().min(180)]))
        );
    }
    let mut elapsed_us: Vec<u128> = Vec::new();
    for trial in 0..trials {
        let t = Instant::now();
        let r = parse_translation_unit(&target, &options);
        let us = t.elapsed().as_micros();
        elapsed_us.push(us);
        eprintln!(
            "[timing] trial  {trial}: {us} us  ({} ms)  -  {}",
            us / 1000,
            r.map(|_| "ok".to_string())
                .unwrap_or_else(|e| format!("ERR {}", &e[..e.len().min(180)]))
        );
    }
    elapsed_us.sort_unstable();
    let median = elapsed_us[elapsed_us.len() / 2];
    let min = elapsed_us[0];
    let max = elapsed_us[elapsed_us.len() - 1];
    eprintln!("");
    eprintln!("[timing] === RESULTS ===");
    eprintln!("[timing] file:    {}", target.display());
    eprintln!("[timing] trials:  {}", trials);
    eprintln!("[timing] min:     {} us  ({} ms)", min, min / 1000);
    eprintln!("[timing] median:  {} us  ({} ms)", median, median / 1000);
    eprintln!("[timing] max:     {} us  ({} ms)", max, max / 1000);
}

#[test]
#[ignore = "real corpus per-file warm cost  -  bypasses summary cache by parsing each file once after pre-warming the per-file caches"]
fn r2_kernel_scripts_per_file_warm_throughput() {
    let corpus_root = Path::new(env!("CARGO_MANIFEST_DIR")).join(CORPUS_ROOT);
    let files = collect_corpus(&corpus_root);
    assert_ne!(files.len(), 0, "corpus must contain .c files");

    let options = kernel_scripts_compile_options();

    // Pre-warm: parse each file once to populate every cache layer.
    eprintln!("[corpus-throughput] prewarming {} files…", files.len());
    let prewarm_start = Instant::now();
    let mut warmed: Vec<&PathBuf> = Vec::new();
    let mut warm_fails: Vec<(PathBuf, String)> = Vec::new();
    for f in &files {
        match parse_translation_unit(f, &options) {
            Ok(_) => warmed.push(f),
            Err(e) => warm_fails.push((f.clone(), e)),
        }
    }
    eprintln!(
        "[corpus-throughput] prewarm: {} ok, {} fail, {:.2}s",
        warmed.len(),
        warm_fails.len(),
        prewarm_start.elapsed().as_secs_f64()
    );
    if std::env::var_os("R2_PRINT_FAILURES").is_some() {
        let mut clusters: BTreeMap<String, usize> = BTreeMap::new();
        for (path, message) in &warm_fails {
            let rel = path.strip_prefix(&corpus_root).unwrap_or(path).display();
            let cluster = classify_error(message);
            *clusters.entry(cluster.clone()).or_insert(0) += 1;
            eprintln!(
                "[corpus-throughput] FAIL {} [{}] :: {}",
                rel,
                cluster,
                &message[..message.len().min(220)].replace('\n', " ")
            );
        }
        eprintln!("[corpus-throughput] failure clusters:");
        for (cluster, count) in &clusters {
            eprintln!("[corpus-throughput]   {count} × {cluster}");
        }
    }

    // Measured run: parse each warmed file again  -  every cache layer hits.
    let measured_start = Instant::now();
    let mut total_ms = 0u128;
    let mut per_file_us: Vec<u128> = Vec::with_capacity(warmed.len());
    for f in &warmed {
        let t = Instant::now();
        let _ = parse_translation_unit(f, &options);
        let us = t.elapsed().as_micros();
        per_file_us.push(us);
        total_ms = total_ms.saturating_add(us / 1000);
    }
    let elapsed = measured_start.elapsed();
    per_file_us.sort_unstable();
    let median = per_file_us.get(per_file_us.len() / 2).copied().unwrap_or(0);
    let mean: u128 = per_file_us.iter().sum::<u128>() / per_file_us.len().max(1) as u128;
    let max = per_file_us.last().copied().unwrap_or(0);
    let elapsed_ms = elapsed.as_secs_f64() * 1000.0;
    let files_per_sec = warmed.len() as f64 / elapsed.as_secs_f64().max(1e-9);

    eprintln!("");
    eprintln!("[corpus-throughput] === WARM-PATH RESULTS ===");
    eprintln!("[corpus-throughput] files measured: {}", warmed.len());
    eprintln!("[corpus-throughput] elapsed total:  {:.2} ms", elapsed_ms);
    eprintln!("[corpus-throughput] mean per file:  {} us", mean);
    eprintln!("[corpus-throughput] median:         {} us", median);
    eprintln!("[corpus-throughput] max:            {} us", max);
    eprintln!("[corpus-throughput] files/sec:      {:.0}", files_per_sec);
    eprintln!(
        "[corpus-throughput] vs ~580 ms baseline: {:.1}x speedup",
        (580_000.0_f64) / mean.max(1) as f64
    );
}

#[test]
#[ignore = "cold-per-file: warm GPU pipeline cache, then measure each new source"]
fn r2_kernel_scripts_cold_per_file_throughput() {
    let corpus_root = Path::new(env!("CARGO_MANIFEST_DIR")).join(CORPUS_ROOT);
    let files = collect_corpus(&corpus_root);
    assert_ne!(files.len(), 0, "corpus must contain .c files");

    let options = kernel_scripts_compile_options();

    // Find the smallest passing file to warm the GPU pipeline cache. Parse it
    // twice so the first cold-compile cost is amortised.
    let mut warm_target: Option<&PathBuf> = None;
    for f in &files {
        if parse_translation_unit(f, &options).is_ok() {
            warm_target = Some(f);
            break;
        }
    }
    let warm_target = warm_target.expect("need at least one passing file to warm");
    eprintln!(
        "[cold-per-file] warming pipeline cache with {}",
        warm_target.display()
    );
    let warm_started = Instant::now();
    for _ in 0..2 {
        let _ = parse_translation_unit(warm_target, &options);
    }
    eprintln!(
        "[cold-per-file] pipeline warmup: {:.2}s",
        warm_started.elapsed().as_secs_f64()
    );

    // Measured: parse every other corpus file once.
    let measured_start = Instant::now();
    let mut per_file_us: Vec<u128> = Vec::new();
    let mut ok = 0usize;
    let mut fail = 0usize;
    for f in &files {
        if std::path::Path::new(f) == std::path::Path::new(warm_target) {
            continue;
        }
        let t = Instant::now();
        let r = parse_translation_unit(f, &options);
        let us = t.elapsed().as_micros();
        if r.is_ok() {
            ok += 1;
            per_file_us.push(us);
        } else {
            fail += 1;
        }
    }
    let elapsed = measured_start.elapsed();
    per_file_us.sort_unstable();
    if per_file_us.is_empty() {
        eprintln!("[cold-per-file] no passing files measured");
        return;
    }
    let median = per_file_us[per_file_us.len() / 2];
    let mean = per_file_us.iter().sum::<u128>() / per_file_us.len() as u128;
    let max = per_file_us.last().copied().unwrap_or(0);
    let elapsed_ms = elapsed.as_secs_f64() * 1000.0;

    eprintln!("");
    eprintln!("[cold-per-file] === COLD-PATH RESULTS (pipeline warm, source cold) ===");
    eprintln!("[cold-per-file] files measured: {} ok, {} fail", ok, fail);
    eprintln!("[cold-per-file] elapsed total:  {:.2} ms", elapsed_ms);
    eprintln!(
        "[cold-per-file] mean per file:  {} us  ({} ms)",
        mean,
        mean / 1000
    );
    eprintln!(
        "[cold-per-file] median:         {} us  ({} ms)",
        median,
        median / 1000
    );
    eprintln!(
        "[cold-per-file] max:            {} us  ({} ms)",
        max,
        max / 1000
    );
    eprintln!(
        "[cold-per-file] vs ~580 ms baseline: {:.1}x speedup",
        (580_000.0_f64) / mean.max(1) as f64
    );
}

