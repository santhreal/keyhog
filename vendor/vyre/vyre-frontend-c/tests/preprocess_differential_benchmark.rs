//! Differential clang-vs-vyre preprocessing benchmark harness for release-plan item 30.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

#[allow(unused_imports)]
use vyre_driver_cuda as _;
#[allow(unused_imports)]
use vyre_driver_wgpu as _;

use vyre::{DispatchConfig, VyreBackend};
use vyre_libs::parsing::c::preprocess::gpu_pipeline::{
    gpu_preprocess_translation_unit, GpuDispatcher, IncludeLoader, MacroDef,
};

struct CountingGpuDispatcher<'a> {
    backend: &'a dyn VyreBackend,
    launches: AtomicU64,
    host_write_bytes: AtomicU64,
    host_readback_bytes: AtomicU64,
    op_counts: Mutex<HashMap<String, OpGpuCounters>>,
}

impl<'a> CountingGpuDispatcher<'a> {
    fn new(backend: &'a dyn VyreBackend) -> Self {
        Self {
            backend,
            launches: AtomicU64::new(0),
            host_write_bytes: AtomicU64::new(0),
            host_readback_bytes: AtomicU64::new(0),
            op_counts: Mutex::new(HashMap::new()),
        }
    }

    fn counters(&self) -> BenchmarkGpuCounters {
        BenchmarkGpuCounters {
            kernel_launch_count: self.launches.load(Ordering::Relaxed),
            host_write_bytes: self.host_write_bytes.load(Ordering::Relaxed),
            host_readback_bytes: self.host_readback_bytes.load(Ordering::Relaxed),
        }
    }

    fn record_dispatch_start(
        &self,
        program: &vyre::ir::Program,
        host_write_bytes: u64,
    ) -> Result<String, String> {
        self.launches.fetch_add(1, Ordering::Relaxed);
        self.host_write_bytes
            .fetch_add(host_write_bytes, Ordering::Relaxed);
        let op_id = program
            .entry_op_id
            .as_deref()
            .unwrap_or("<anonymous>")
            .to_string();
        let mut op_counts = self
            .op_counts
            .lock()
            .map_err(|error| format!("benchmark op counter lock poisoned: {error}"))?;
        let entry = op_counts.entry(op_id.clone()).or_default();
        entry.kernel_launch_count = entry.kernel_launch_count.saturating_add(1);
        entry.host_write_bytes = entry.host_write_bytes.saturating_add(host_write_bytes);
        Ok(op_id)
    }

    fn record_dispatch_end(&self, op_id: &str, host_readback_bytes: u64) -> Result<(), String> {
        self.host_readback_bytes
            .fetch_add(host_readback_bytes, Ordering::Relaxed);
        let mut op_counts = self
            .op_counts
            .lock()
            .map_err(|error| format!("benchmark op counter lock poisoned: {error}"))?;
        let entry = op_counts.entry(op_id.to_string()).or_default();
        entry.host_readback_bytes = entry
            .host_readback_bytes
            .saturating_add(host_readback_bytes);
        Ok(())
    }

    fn format_top_ops(&self, limit: usize) -> Result<String, String> {
        let mut rows = self
            .op_counts
            .lock()
            .map_err(|error| format!("benchmark op counter lock poisoned: {error}"))?
            .iter()
            .map(|(op, counts)| (op.clone(), *counts))
            .collect::<Vec<_>>();
        rows.sort_unstable_by(|left, right| {
            right
                .1
                .kernel_launch_count
                .cmp(&left.1.kernel_launch_count)
                .then_with(|| right.1.host_readback_bytes.cmp(&left.1.host_readback_bytes))
                .then_with(|| right.1.host_write_bytes.cmp(&left.1.host_write_bytes))
                .then_with(|| left.0.cmp(&right.0))
        });
        let mut out = String::from("[preprocess-op-counts]");
        for (rank, (op, counts)) in rows.into_iter().take(limit).enumerate() {
            out.push_str(&format!(
                "\nrank={} launches={} host_write={} host_readback={} op={}",
                rank + 1,
                counts.kernel_launch_count,
                counts.host_write_bytes,
                counts.host_readback_bytes,
                op
            ));
        }
        Ok(out)
    }
}

impl GpuDispatcher for CountingGpuDispatcher<'_> {
    fn dispatch(
        &self,
        program: &vyre::ir::Program,
        inputs: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, String> {
        let op_id = self.record_dispatch_start(
            program,
            inputs.iter().map(|input| input.len() as u64).sum::<u64>(),
        )?;
        let outputs = self
            .backend
            .dispatch(program, inputs, &DispatchConfig::default())
            .map_err(|error| format!("backend dispatch: {error}"))?;
        self.record_dispatch_end(
            &op_id,
            outputs
                .iter()
                .map(|output| output.len() as u64)
                .sum::<u64>(),
        )?;
        Ok(outputs)
    }

    fn dispatch_borrowed(
        &self,
        program: &vyre::ir::Program,
        inputs: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>, String> {
        let op_id = self.record_dispatch_start(
            program,
            inputs.iter().map(|input| input.len() as u64).sum::<u64>(),
        )?;
        let outputs = self
            .backend
            .dispatch_borrowed(program, inputs, &DispatchConfig::default())
            .map_err(|error| format!("backend dispatch_borrowed: {error}"))?;
        self.record_dispatch_end(
            &op_id,
            outputs
                .iter()
                .map(|output| output.len() as u64)
                .sum::<u64>(),
        )?;
        Ok(outputs)
    }
}

struct FilesystemLoader {
    include_roots: Vec<PathBuf>,
    loaded_include_bytes: AtomicU64,
}

impl FilesystemLoader {
    fn new(include_roots: Vec<PathBuf>) -> Self {
        Self {
            include_roots,
            loaded_include_bytes: AtomicU64::new(0),
        }
    }

    fn loaded_include_bytes(&self) -> u64 {
        self.loaded_include_bytes.load(Ordering::Relaxed)
    }
}

impl IncludeLoader for FilesystemLoader {
    fn load(
        &self,
        path: &[u8],
        is_system: bool,
        _is_next: bool,
        from: &Path,
    ) -> Result<Option<(PathBuf, std::sync::Arc<[u8]>)>, String> {
        let name = std::str::from_utf8(path).map_err(|error| error.to_string())?;
        let local_dir = from.parent().filter(|_| !is_system);
        let resolved = local_dir
            .into_iter()
            .map(|dir| dir.join(name))
            .chain(self.include_roots.iter().map(|root| root.join(name)))
            .find(|candidate| candidate.exists())
            .ok_or_else(|| {
                format!(
                    "include {name} not found from {} in {:?}",
                    from.display(),
                    self.include_roots
                )
            })?;
        let bytes = std::fs::read(&resolved)
            .map_err(|error| format!("read include {}: {error}", resolved.display()))?;
        self.loaded_include_bytes
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        Ok(Some((resolved, bytes.into())))
    }
}

#[derive(Debug, Clone, Copy)]
struct BenchmarkGpuCounters {
    kernel_launch_count: u64,
    host_write_bytes: u64,
    host_readback_bytes: u64,
}

#[derive(Debug, Clone, Copy, Default)]
struct OpGpuCounters {
    kernel_launch_count: u64,
    host_write_bytes: u64,
    host_readback_bytes: u64,
}

#[derive(Debug)]
struct DifferentialPreprocessBenchmarkReport {
    target_id: String,
    subsystem_translation_units: usize,
    corpus_bytes: u64,
    clang_wall_ns: u64,
    vyre_wall_ns: u64,
    clang_bytes_per_second: u64,
    vyre_bytes_per_second: u64,
    gpu: BenchmarkGpuCounters,
}

impl DifferentialPreprocessBenchmarkReport {
    fn validate(&self) {
        assert_eq!(self.target_id, "linux-lib-math-v6.8");
        assert_eq!(self.subsystem_translation_units, 12);
        assert!(self.corpus_bytes > 0);
        assert!(self.clang_wall_ns > 0);
        assert!(self.vyre_wall_ns > 0);
        assert!(self.clang_bytes_per_second > 0);
        assert!(self.vyre_bytes_per_second > 0);
        assert!(self.gpu.kernel_launch_count > 0);
        assert!(self.gpu.host_write_bytes > 0);
        assert!(self.gpu.host_readback_bytes > 0);
    }
}

#[test]
fn differential_preprocess_benchmark_reports_clang_vyre_and_gpu_counters() {
    let manifest: toml::Value = toml::from_str(include_str!("../parity/linux_math_v6_8.toml"))
        .expect("release parity manifest parses");
    let target_id = manifest["id"]
        .as_str()
        .expect("manifest id exists")
        .to_string();
    let subsystem_translation_units = manifest["files"]["sources"]
        .as_array()
        .expect("manifest source list exists")
        .len();

    let root = std::env::temp_dir().join(format!("vyre-preprocess-bench-{}", std::process::id()));
    std::fs::create_dir_all(&root).expect("benchmark temp dir exists");
    let header = root.join("bench.h");
    let source = root.join("tu.c");
    std::fs::write(
        &header,
        concat!(
            "#pragma once\n",
            "#define SCALE 21\n",
            "int header_value;\n",
        ),
    )
    .expect("write benchmark header");
    let source_bytes = concat!(
        "#include \"bench.h\"\n",
        "#include \"bench.h\"\n",
        "#if SCALE\n",
        "int scaled_value = SCALE;\n",
        "#endif\n",
    )
    .as_bytes()
    .to_vec();
    std::fs::write(&source, &source_bytes).expect("write benchmark source");

    let clang_start = Instant::now();
    let clang = clang_command()
        .arg("-E")
        .arg("-P")
        .arg("-x")
        .arg("c")
        .arg("-I")
        .arg(&root)
        .arg(&source)
        .output()
        .expect("clang must be installed for differential preprocessing benchmark");
    let clang_wall_ns = clang_start.elapsed().as_nanos() as u64;
    assert!(
        clang.status.success(),
        "clang preprocessing failed: {}",
        String::from_utf8_lossy(&clang.stderr)
    );

    let backend =
        vyre::backend::acquire_preferred_dispatch_backend().expect("GPU backend must be available");
    let dispatcher = CountingGpuDispatcher::new(backend.as_ref());
    let loader = FilesystemLoader::new(vec![root.clone()]);

    let vyre_start = Instant::now();
    let vyre = gpu_preprocess_translation_unit(&dispatcher, &loader, &source, &source_bytes, &[])
        .expect("vyre GPU preprocessing succeeds");
    let vyre_wall_ns = vyre_start.elapsed().as_nanos() as u64;
    let counters = dispatcher.counters();
    let corpus_bytes = source_bytes.len() as u64 + loader.loaded_include_bytes();

    let report = DifferentialPreprocessBenchmarkReport {
        target_id,
        subsystem_translation_units,
        corpus_bytes,
        clang_wall_ns,
        vyre_wall_ns,
        clang_bytes_per_second: bytes_per_second(corpus_bytes, clang_wall_ns),
        vyre_bytes_per_second: bytes_per_second(corpus_bytes, vyre_wall_ns),
        gpu: counters,
    };

    let clang_text = String::from_utf8_lossy(&clang.stdout);
    let vyre_text = String::from_utf8_lossy(&vyre.bytes);
    assert!(clang_text.contains("scaled_value"));
    assert!(vyre_text.contains("scaled_value"));
    assert!(clang_text.contains("21"));
    assert!(vyre_text.contains("21"));
    assert!(vyre
        .include_acceleration_events
        .iter()
        .any(|event| event.skipped_include));
    report.validate();
}

#[test]
#[ignore = "requires VYRE_LINUX_V68_ROOT pointing at Linux v6.8 source tree"]
fn full_linux_lib_math_preprocess_benchmark_report_when_root_is_configured() {
    let manifest: toml::Value = toml::from_str(include_str!("../parity/linux_math_v6_8.toml"))
        .expect("release parity manifest parses");
    let root = std::env::var_os("VYRE_LINUX_V68_ROOT")
        .map(PathBuf::from)
        .expect("set VYRE_LINUX_V68_ROOT to the Linux v6.8 source root");
    let target_id = manifest["id"]
        .as_str()
        .expect("manifest id exists")
        .to_string();
    let mut sources = manifest["files"]["sources"]
        .as_array()
        .expect("manifest source list exists")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("source path must be string")
                .to_string()
        })
        .collect::<Vec<_>>();
    let full_source_count = sources.len();
    if let Ok(max_tus) = std::env::var("VYRE_LINUX_V68_MAX_TUS") {
        let max_tus = max_tus
            .parse::<usize>()
            .expect("VYRE_LINUX_V68_MAX_TUS must be a positive integer");
        assert!(max_tus > 0, "VYRE_LINUX_V68_MAX_TUS must be positive");
        sources.truncate(max_tus);
    }
    let include_roots = linux_include_roots(&root);
    let backend =
        vyre::backend::acquire_preferred_dispatch_backend().expect("GPU backend must be available");
    let dispatcher = CountingGpuDispatcher::new(backend.as_ref());
    let loader = FilesystemLoader::new(include_roots.clone());
    let kernel_macros = clang_kernel_predefined_macros();

    let mut corpus_bytes = 0_u64;
    let clang_start = Instant::now();
    let mut clang_output_bytes = 0_u64;
    for source in &sources {
        let path = root.join(source);
        let output = clang_preprocess(&root, &include_roots, &path);
        clang_output_bytes = clang_output_bytes.saturating_add(output.len() as u64);
    }
    let clang_wall_ns = clang_start.elapsed().as_nanos() as u64;

    let vyre_start = Instant::now();
    let mut vyre_output_bytes = 0_u64;
    for source in &sources {
        let path = root.join(source);
        let source_bytes =
            std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        let mut bytes = b"#include <linux/kconfig.h>\n".to_vec();
        bytes.extend_from_slice(&source_bytes);
        let preprocessed =
            gpu_preprocess_translation_unit(&dispatcher, &loader, &path, &bytes, &kernel_macros)
                .unwrap_or_else(|error| panic!("vyre preprocess {}: {error}", path.display()));
        vyre_output_bytes = vyre_output_bytes.saturating_add(preprocessed.bytes.len() as u64);
    }
    corpus_bytes = corpus_bytes
        .saturating_add(
            sources
                .iter()
                .map(|source| {
                    let path = root.join(source);
                    let source_len = std::fs::metadata(&path)
                        .unwrap_or_else(|error| panic!("metadata {}: {error}", path.display()))
                        .len();
                    source_len + b"#include <linux/kconfig.h>\n".len() as u64
                })
                .sum::<u64>(),
        )
        .saturating_add(loader.loaded_include_bytes());
    let vyre_wall_ns = vyre_start.elapsed().as_nanos() as u64;
    let counters = dispatcher.counters();
    let report = DifferentialPreprocessBenchmarkReport {
        target_id,
        subsystem_translation_units: sources.len(),
        corpus_bytes,
        clang_wall_ns,
        vyre_wall_ns,
        clang_bytes_per_second: bytes_per_second(corpus_bytes, clang_wall_ns),
        vyre_bytes_per_second: bytes_per_second(corpus_bytes, vyre_wall_ns),
        gpu: counters,
    };

    if std::env::var_os("VYRE_LINUX_V68_MAX_TUS").is_none() {
        assert_eq!(sources.len(), 12);
    }
    assert!(clang_output_bytes > 0);
    assert!(vyre_output_bytes > 0);
    if sources.len() == full_source_count {
        report.validate();
        assert_required_preprocess_speedup(&report);
    }
    eprintln!("{}", format_report(&report));
    if std::env::var_os("VYRE_PREPROC_OP_COUNTS").is_some() {
        eprintln!(
            "{}",
            dispatcher
                .format_top_ops(40)
                .expect("format benchmark op counts")
        );
    }
}


fn clang_kernel_predefined_macros() -> Vec<MacroDef> {
    [
        ("__KERNEL__", "1"),
        ("__clang__", "1"),
        ("__clang_major__", "18"),
        ("__clang_minor__", "1"),
        ("__clang_patchlevel__", "3"),
        ("__GNUC__", "4"),
        ("__GNUC_MINOR__", "2"),
        ("__GNUC_PATCHLEVEL__", "1"),
        ("__x86_64__", "1"),
        ("__x86_64", "1"),
        ("__amd64__", "1"),
        ("__amd64", "1"),
        ("__LP64__", "1"),
        ("_LP64", "1"),
        ("__CHAR_BIT__", "8"),
        ("__SIZEOF_INT128__", "16"),
        ("__SIZEOF_LONG__", "8"),
        ("__SIZEOF_LONG_LONG__", "8"),
        ("__SIZEOF_POINTER__", "8"),
        ("__BYTE_ORDER", "__LITTLE_ENDIAN"),
        ("__LITTLE_ENDIAN", "1234"),
        ("__BIG_ENDIAN", "4321"),
        ("__LITTLE_ENDIAN_BITFIELD", "1"),
    ]
    .into_iter()
    .map(|(name, body)| MacroDef {
        name: name.as_bytes().to_vec().into(),
        args: Vec::new(),
        body: body.as_bytes().to_vec().into(),
        is_function_like: false,
    })
    .collect()
}

fn linux_include_roots(root: &Path) -> Vec<PathBuf> {
    let build_root = std::env::var_os("VYRE_LINUX_V68_BUILD")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            root.parent()
                .map(|parent| {
                    parent.join(format!(
                        "{}-build",
                        root.file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or("linux-v6.8")
                    ))
                })
                .unwrap_or_else(|| root.join("build"))
        });
    let asm_overlay = std::env::temp_dir().join(format!(
        "vyre-linux-v6.8-asm-overlay-{}",
        std::process::id()
    ));
    let asm_dir = asm_overlay.join("asm");
    std::fs::create_dir_all(&asm_dir).expect("create asm-generic overlay");
    if let Ok(entries) = std::fs::read_dir(root.join("include/asm-generic")) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|extension| extension == "h") {
                let dest = asm_dir.join(path.file_name().expect("asm-generic file name"));
                if !dest.exists() {
                    std::fs::copy(&path, &dest).unwrap_or_else(|error| {
                        panic!(
                            "copy asm-generic fallback {} to {}: {error}",
                            path.display(),
                            dest.display()
                        )
                    });
                }
            }
        }
    }
    let mut roots = vec![
        build_root.join("arch/x86/include/generated"),
        build_root.join("arch/x86/include/generated/uapi"),
        build_root.join("include"),
        build_root.join("include/generated"),
        build_root.join("include/generated/uapi"),
    ];
    roots.extend(
        [
            "arch/x86/include",
            "arch/x86/include/generated",
            "arch/x86/include/uapi",
            "arch/x86/include/generated/uapi",
            "include",
            "include/generated",
            "include/uapi",
            "include/generated/uapi",
            "tools/include",
        ]
        .into_iter()
        .map(|relative| root.join(relative)),
    );
    roots.push(asm_overlay);
    roots
}

fn clang_preprocess(root: &Path, include_roots: &[PathBuf], path: &Path) -> Vec<u8> {
    let mut command = clang_command();
    command
        .arg("-E")
        .arg("-P")
        .arg("-x")
        .arg("c")
        .arg("-D__KERNEL__")
        .arg("-include")
        .arg("linux/kconfig.h")
        .current_dir(root);
    for include_root in include_roots {
        command.arg("-I").arg(include_root);
    }
    let output = command
        .arg(path)
        .output()
        .unwrap_or_else(|error| panic!("spawn clang for {}: {error}", path.display()));
    assert!(
        output.status.success(),
        "clang preprocess {} failed: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn clang_command() -> Command {
    Command::new(resolve_clang_path())
}

fn resolve_clang_path() -> PathBuf {
    for var in ["VYRE_CLANG", "CLANG"] {
        if let Some(path) = std::env::var_os(var).map(PathBuf::from) {
            assert!(
                path.exists(),
                "{var} points to missing clang executable {}",
                path.display()
            );
            return path;
        }
    }
    for name in ["clang", "clang-18", "clang-17", "clang-16", "clang-15"] {
        if let Some(path) = find_executable_in_path(name) {
            return path;
        }
    }
    for path in ["/usr/bin/clang", "/usr/local/bin/clang"] {
        let path = PathBuf::from(path);
        if path.exists() {
            return path;
        }
    }
    panic!(
        "clang executable not found. Fix: install clang or set VYRE_CLANG to the absolute clang path for the differential preprocessing benchmark."
    );
}

fn find_executable_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

fn format_report(report: &DifferentialPreprocessBenchmarkReport) -> String {
    format!(
        "target={} tus={} bytes={} clang_ns={} vyre_ns={} clang_Bps={} vyre_Bps={} launches={} host_write={} host_readback={}",
        report.target_id,
        report.subsystem_translation_units,
        report.corpus_bytes,
        report.clang_wall_ns,
        report.vyre_wall_ns,
        report.clang_bytes_per_second,
        report.vyre_bytes_per_second,
        report.gpu.kernel_launch_count,
        report.gpu.host_write_bytes,
        report.gpu.host_readback_bytes
    )
}

fn assert_required_preprocess_speedup(report: &DifferentialPreprocessBenchmarkReport) {
    let required = std::env::var("VYRE_REQUIRED_PREPROCESS_SPEEDUP")
        .ok()
        .map(|value| {
            value
                .parse::<u64>()
                .expect("VYRE_REQUIRED_PREPROCESS_SPEEDUP must be a positive integer")
        })
        .unwrap_or(100);
    assert!(
        required > 0,
        "VYRE_REQUIRED_PREPROCESS_SPEEDUP must be positive"
    );
    let required_vyre_ns = report.clang_wall_ns / required;
    assert!(
        report.vyre_wall_ns <= required_vyre_ns.max(1),
        "Vyre preprocessing did not meet the required {required}x clang speedup for {}: {}",
        report.target_id,
        format_report(report)
    );
}

fn bytes_per_second(bytes: u64, wall_ns: u64) -> u64 {
    ((bytes as u128 * 1_000_000_000_u128) / wall_ns.max(1) as u128) as u64
}

