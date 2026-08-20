//! WHY: Production release builds must strictly enforce symbol stripping and zero DWARF
//! debuginfo bloat in workspace Cargo.toml `[profile.release]` while preserving panic unwind
//! tables for catch_unwind isolation boundaries. Shipped release binary artifacts must not
//! carry unstripped symbol tables or DWARF debug sections.
//!
//! What it closes:
//! Closes the release binary debug bloat defect where unstripped debug symbols or DWARF sections
//! leak into production release artifacts, inflating download sizes and runtime memory footprint.
//!
//! What it does not catch:
//! Host-specific dynamic linker symbol resolution or third-party C library strip tool variations.

use std::collections::HashSet;
use std::path::PathBuf;

/// Semantic keys affecting safety or runtime execution semantics.
const SEMANTIC_KEYS: &[&str] = &["panic", "overflow-checks", "debug-assertions", "rpath"];

/// Cosmetic and compiler optimization keys.
const COSMETIC_PERF_KEYS: &[&str] = &[
    "opt-level",
    "lto",
    "codegen-units",
    "strip",
    "debug",
    "incremental",
    "inherits",
    "split-debuginfo",
    "panic-strategy",
];

fn known_keys() -> HashSet<&'static str> {
    let mut keys = HashSet::new();
    for &k in SEMANTIC_KEYS {
        keys.insert(k);
    }
    for &k in COSMETIC_PERF_KEYS {
        keys.insert(k);
    }
    keys
}

fn locate_workspace_cargo_toml() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut current = Some(manifest_dir.as_path());
    while let Some(dir) = current {
        let candidate = dir.join("Cargo.toml");
        if candidate.is_file() {
            if let Ok(content) = std::fs::read_to_string(&candidate) {
                if content.contains("[workspace]") {
                    return candidate;
                }
            }
        }
        current = dir.parent();
    }
    manifest_dir.join("../../Cargo.toml")
}

#[derive(Debug, PartialEq, Eq)]
struct ProfileValidationResult {
    errors: Vec<String>,
}

fn validate_profile_table(parsed: &toml::Table) -> ProfileValidationResult {
    let mut errors = Vec::new();
    let profile_table = match parsed.get("profile").and_then(|v| v.as_table()) {
        Some(t) => t,
        None => {
            errors.push("Missing [profile] section in Cargo.toml".to_string());
            return ProfileValidationResult { errors };
        }
    };

    let allowed = known_keys();

    // Dynamically derive variant space from all profiles present in the table.
    for (profile_name, profile_val) in profile_table {
        let subtable = match profile_val.as_table() {
            Some(t) => t,
            None => continue,
        };

        for (key, _) in subtable {
            if !allowed.contains(key.as_str()) {
                errors.push(format!(
                    "Unclassified key in [profile.{profile_name}]: '{key}'. Must be classified as SEMANTIC or COSMETIC_PERF."
                ));
            }
        }
    }

    let release = match profile_table.get("release").and_then(|v| v.as_table()) {
        Some(t) => t,
        None => {
            errors.push("Missing required [profile.release] section".to_string());
            return ProfileValidationResult { errors };
        }
    };

    // Assert strip = "symbols" (or boolean true)
    match release.get("strip") {
        Some(val) => {
            let is_valid = val.as_str() == Some("symbols") || val.as_bool() == Some(true);
            if !is_valid {
                errors.push(format!(
                    "[profile.release] strip must be \"symbols\", got {val:?}"
                ));
            }
        }
        None => {
            errors.push("[profile.release] missing required `strip = \"symbols\"`".to_string());
        }
    }

    // Assert debug = false (or 0) to eliminate DWARF debuginfo bloat
    // Assert debug = false, 0, or "none" to eliminate DWARF debuginfo bloat
    match release.get("debug") {
        Some(val) => {
            let is_false = val.as_bool() == Some(false)
                || val.as_integer() == Some(0)
                || val.as_str() == Some("none");
            if !is_false {
                errors.push(format!(
                    "[profile.release] debug must be false or 0 to eliminate DWARF bloat, got {val:?}"
                ));
            }
        }
        None => {
            errors.push("[profile.release] missing required `debug = false`".to_string());
        }
    }

    // Assert panic = "unwind"
    match release.get("panic").and_then(|v| v.as_str()) {
        Some("unwind") => {}
        other => {
            errors.push(format!(
                "[profile.release] panic must be \"unwind\" for catch_unwind boundaries, got {other:?}"
            ));
        }
    }

    // Assert overflow-checks = true
    match release.get("overflow-checks").and_then(|v| v.as_bool()) {
        Some(true) => {}
        other => {
            errors.push(format!(
                "[profile.release] overflow-checks must be true, got {other:?}"
            ));
        }
    }

    // Assert opt-level = 3
    match release.get("opt-level").and_then(|v| v.as_integer()) {
        Some(3) => {}
        other => {
            errors.push(format!(
                "[profile.release] opt-level must be 3, got {other:?}"
            ));
        }
    }

    // Assert lto = "fat"
    match release.get("lto").and_then(|v| v.as_str()) {
        Some("fat") => {}
        other => {
            errors.push(format!(
                "[profile.release] lto must be \"fat\", got {other:?}"
            ));
        }
    }

    // Assert codegen-units = 1
    match release.get("codegen-units").and_then(|v| v.as_integer()) {
        Some(1) => {}
        other => {
            errors.push(format!(
                "[profile.release] codegen-units must be 1, got {other:?}"
            ));
        }
    }

    ProfileValidationResult { errors }
}

fn check_macho_segments_and_sections(
    segments: &[goblin::mach::segment::Segment],
    label: &str,
    violations: &mut Vec<String>,
) {
    for segment in segments {
        if let Ok(seg_name) = segment.name() {
            if seg_name == "__DWARF" {
                violations.push(format!("Unstripped __DWARF segment found in {label}"));
            }
        }
        for (section, _) in segment.into_iter().flatten() {
            if let Ok(sec_name) = section.name() {
                if sec_name.starts_with("__debug_") || sec_name.starts_with(".debug_") {
                    violations.push(format!(
                        "Unstripped DWARF section found in {label}: {sec_name}"
                    ));
                }
            }
        }
    }
}

/// Validate binary bytes to ensure no DWARF debuginfo sections or unstripped symbol tables exist.
fn validate_stripped_binary_bytes(bytes: &[u8]) -> Result<(), Vec<String>> {
    let mut violations = Vec::new();

    if bytes.len() < 4 {
        violations.push("Binary payload too short to determine object format".to_string());
        return Err(violations);
    }

    let parsed = match goblin::Object::parse(bytes) {
        Ok(obj) => obj,
        Err(err) => {
            violations.push(format!("Failed to parse object format: {err}"));
            return Err(violations);
        }
    };

    match parsed {
        goblin::Object::Elf(elf) => {
            // Check section headers for debuginfo / DWARF bloat
            for section in &elf.section_headers {
                if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                    if name.starts_with(".debug_") || name.starts_with(".zdebug_") {
                        violations.push(format!(
                            "Unstripped DWARF debug section found in ELF: {name}"
                        ));
                    }
                    if name == ".symtab" && section.sh_size > 0 {
                        violations.push(
                            "Unstripped static symbol table (.symtab) found in ELF binary"
                                .to_string(),
                        );
                    }
                }
            }
        }
        goblin::Object::Mach(mach) => match mach {
            goblin::mach::Mach::Binary(macho) => {
                check_macho_segments_and_sections(
                    &macho.segments,
                    "Mach-O binary",
                    &mut violations,
                );
            }
            goblin::mach::Mach::Fat(fat) => match fat.arches() {
                Ok(arches) => {
                    for arch in arches {
                        let arch_bytes = arch.slice(bytes);
                        match goblin::mach::MachO::parse(arch_bytes, 0) {
                            Ok(sub_macho) => check_macho_segments_and_sections(
                                &sub_macho.segments,
                                "Fat Mach-O binary",
                                &mut violations,
                            ),
                            Err(err) => {
                                violations.push(format!("Failed to parse Fat Mach-O slice: {err}"))
                            }
                        }
                    }
                }
                Err(err) => {
                    violations.push(format!("Failed to enumerate Fat Mach-O arches: {err}"))
                }
            },
        },
        goblin::Object::PE(pe) => {
            for section in &pe.sections {
                if let Ok(name) = section.name() {
                    if name.starts_with(".debug") {
                        violations.push(format!(
                            "Unstripped debug section found in PE binary: {name}"
                        ));
                    }
                }
            }
        }
        goblin::Object::Archive(_) => {
            violations.push("Unexpected archive object; expected executable binary".to_string());
        }
        goblin::Object::Unknown(_) => {
            violations.push("Unknown executable object format".to_string());
        }
        _ => {
            violations.push("Unrecognized executable object variant".to_string());
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

/// Construct a minimal synthetic 64-bit ELF binary for testing strip verification and mutation gating.
fn build_synthetic_elf(include_debug_section: bool, include_symtab: bool) -> Vec<u8> {
    let mut bytes = Vec::new();

    // 1. ELF Header (64-bit, Little Endian, x86-64)
    bytes.extend_from_slice(&[0x7f, b'E', b'L', b'F']); // Magic
    bytes.push(2); // 64-bit
    bytes.push(1); // Little endian
    bytes.push(1); // ELF version
    bytes.push(0); // System V ABI
    bytes.extend_from_slice(&[0u8; 8]); // Padding

    bytes.extend_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
    bytes.extend_from_slice(&0x3eu16.to_le_bytes()); // e_machine = EM_X86_64
    bytes.extend_from_slice(&1u32.to_le_bytes()); // e_version = 1
    bytes.extend_from_slice(&0x400000u64.to_le_bytes()); // e_entry
    bytes.extend_from_slice(&64u64.to_le_bytes()); // e_phoff (immediately after ELF header)

    // Calculate section header offset later
    let e_shoff_pos = bytes.len();
    bytes.extend_from_slice(&0u64.to_le_bytes()); // placeholder for e_shoff

    bytes.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    bytes.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize = 64
    bytes.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize = 56
    bytes.extend_from_slice(&1u16.to_le_bytes()); // e_phnum = 1
    bytes.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize = 64

    // We will have:
    // 0: NULL section
    // 1: .shstrtab (section name string table)
    // 2: .text (code)
    // optionally 3: .debug_info
    // optionally 4: .symtab
    let mut shnum: u16 = 3;
    if include_debug_section {
        shnum += 1;
    }
    if include_symtab {
        shnum += 1;
    }
    bytes.extend_from_slice(&shnum.to_le_bytes()); // e_shnum
    bytes.extend_from_slice(&1u16.to_le_bytes()); // e_shstrndx = 1

    // 2. Program Header (PT_LOAD) - 56 bytes
    bytes.extend_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
    bytes.extend_from_slice(&5u32.to_le_bytes()); // p_flags = PF_R | PF_X
    bytes.extend_from_slice(&0u64.to_le_bytes()); // p_offset
    bytes.extend_from_slice(&0x400000u64.to_le_bytes()); // p_vaddr
    bytes.extend_from_slice(&0x400000u64.to_le_bytes()); // p_paddr
    bytes.extend_from_slice(&0x1000u64.to_le_bytes()); // p_filesz
    bytes.extend_from_slice(&0x1000u64.to_le_bytes()); // p_memsz
    bytes.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align

    // 3. Payload: .text section
    let text_offset = bytes.len() as u64;
    let text_content = [0xc3u8; 16]; // ret instructions
    bytes.extend_from_slice(&text_content);
    let text_size = text_content.len() as u64;

    // 4. Section string table (.shstrtab)
    let shstrtab_offset = bytes.len() as u64;
    let mut shstrtab = Vec::new();
    shstrtab.push(0); // index 0: ""

    let shstrtab_name_idx = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".shstrtab\0");

    let text_name_idx = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".text\0");

    let debug_name_idx = if include_debug_section {
        let idx = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".debug_info\0");
        idx
    } else {
        0
    };

    let symtab_name_idx = if include_symtab {
        let idx = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".symtab\0");
        idx
    } else {
        0
    };

    bytes.extend_from_slice(&shstrtab);
    let shstrtab_size = shstrtab.len() as u64;

    // Optional debug payload
    let (debug_offset, debug_size) = if include_debug_section {
        let off = bytes.len() as u64;
        let debug_bytes = b"DWARF_DEBUG_INFO_BLOB";
        bytes.extend_from_slice(debug_bytes);
        (off, debug_bytes.len() as u64)
    } else {
        (0, 0)
    };

    // Optional symtab payload
    let (symtab_offset, symtab_size) = if include_symtab {
        let off = bytes.len() as u64;
        let symtab_bytes = [0u8; 48]; // 2 symbols (24 bytes each)
        bytes.extend_from_slice(&symtab_bytes);
        (off, symtab_bytes.len() as u64)
    } else {
        (0, 0)
    };

    // Align to 8 bytes for section header table
    while bytes.len() % 8 != 0 {
        bytes.push(0);
    }

    let shoff = bytes.len() as u64;
    // Write shoff back to ELF header
    bytes[e_shoff_pos..e_shoff_pos + 8].copy_from_slice(&shoff.to_le_bytes());

    // Helper to append a 64-byte section header
    let append_shdr = |buf: &mut Vec<u8>,
                       sh_name: u32,
                       sh_type: u32,
                       sh_flags: u64,
                       sh_addr: u64,
                       sh_offset: u64,
                       sh_size: u64,
                       sh_link: u32,
                       sh_info: u32,
                       sh_addralign: u64,
                       sh_entsize: u64| {
        buf.extend_from_slice(&sh_name.to_le_bytes());
        buf.extend_from_slice(&sh_type.to_le_bytes());
        buf.extend_from_slice(&sh_flags.to_le_bytes());
        buf.extend_from_slice(&sh_addr.to_le_bytes());
        buf.extend_from_slice(&sh_offset.to_le_bytes());
        buf.extend_from_slice(&sh_size.to_le_bytes());
        buf.extend_from_slice(&sh_link.to_le_bytes());
        buf.extend_from_slice(&sh_info.to_le_bytes());
        buf.extend_from_slice(&sh_addralign.to_le_bytes());
        buf.extend_from_slice(&sh_entsize.to_le_bytes());
    };

    // Section 0: SHT_NULL
    append_shdr(&mut bytes, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

    // Section 1: .shstrtab (SHT_STRTAB = 3)
    append_shdr(
        &mut bytes,
        shstrtab_name_idx,
        3,
        0,
        0,
        shstrtab_offset,
        shstrtab_size,
        0,
        0,
        1,
        0,
    );

    // Section 2: .text (SHT_PROGBITS = 1, SHF_ALLOC | SHF_EXECINSTR = 6)
    append_shdr(
        &mut bytes,
        text_name_idx,
        1,
        6,
        0x400000 + text_offset,
        text_offset,
        text_size,
        0,
        0,
        16,
        0,
    );

    // Section 3 (optional): .debug_info (SHT_PROGBITS = 1)
    if include_debug_section {
        append_shdr(
            &mut bytes,
            debug_name_idx,
            1,
            0,
            0,
            debug_offset,
            debug_size,
            0,
            0,
            1,
            0,
        );
    }

    // Section 4 (optional): .symtab (SHT_SYMTAB = 2)
    if include_symtab {
        append_shdr(
            &mut bytes,
            symtab_name_idx,
            2,
            0,
            0,
            symtab_offset,
            symtab_size,
            1,
            1,
            8,
            24,
        );
    }

    bytes
}

#[test]
fn regression_row_139_workspace_cargo_toml_release_profile_invariants() {
    let cargo_path = locate_workspace_cargo_toml();
    assert!(
        cargo_path.is_file(),
        "Workspace Cargo.toml must exist at {}",
        cargo_path.display()
    );

    let content = std::fs::read_to_string(&cargo_path).expect("read workspace Cargo.toml");
    let parsed: toml::Table = content.parse().expect("parse workspace Cargo.toml as TOML");

    let result = validate_profile_table(&parsed);
    assert!(
        result.errors.is_empty(),
        "Workspace Cargo.toml [profile.release] violates release profile contracts: {:?}",
        result.errors
    );
}

#[test]
fn regression_row_139_profile_inheritance_and_divergence_contracts() {
    let cargo_path = locate_workspace_cargo_toml();
    let content = std::fs::read_to_string(&cargo_path).expect("read workspace Cargo.toml");
    let parsed: toml::Table = content.parse().expect("parse workspace Cargo.toml as TOML");

    let profile_table = parsed
        .get("profile")
        .and_then(|v| v.as_table())
        .expect("profile table in Cargo.toml");

    // Verify release-fast overrides strip to "none" for CI test backtrace fidelity
    let release_fast = profile_table
        .get("release-fast")
        .and_then(|v| v.as_table())
        .expect("[profile.release-fast] must exist");
    assert_eq!(
        release_fast.get("inherits").and_then(|v| v.as_str()),
        Some("release"),
        "[profile.release-fast] must inherit from release"
    );
    assert_eq!(
        release_fast.get("strip").and_then(|v| v.as_str()),
        Some("none"),
        "[profile.release-fast] must explicitly set strip = \"none\" for CI test diagnostics"
    );
    assert_eq!(
        release_fast
            .get("debug-assertions")
            .and_then(|v| v.as_bool()),
        Some(true),
        "[profile.release-fast] must enable debug-assertions for CI safety invariant verification"
    );

    // Verify bench profile preserves symbols for flamegraph profiling
    let bench = profile_table
        .get("bench")
        .and_then(|v| v.as_table())
        .expect("[profile.bench] must exist");
    assert_eq!(
        bench.get("inherits").and_then(|v| v.as_str()),
        Some("release"),
        "[profile.bench] must inherit from release"
    );
    assert_eq!(
        bench.get("strip").and_then(|v| v.as_str()),
        Some("none"),
        "[profile.bench] must explicitly set strip = \"none\" for benchmark symbol resolution"
    );
    assert_eq!(
        bench.get("debug").and_then(|v| v.as_str()),
        Some("line-tables-only"),
        "[profile.bench] must configure debug = \"line-tables-only\" for flamegraph attribution"
    );
}

#[test]
fn regression_row_139_profile_mutation_gating() {
    let valid_base = r#"
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
panic = "unwind"
strip = "symbols"
debug = false
incremental = false
overflow-checks = true

[profile.release-fast]
inherits = "release"
lto = "thin"
codegen-units = 16
strip = "none"
debug-assertions = true
"#;

    let parsed_valid: toml::Table = valid_base.parse().expect("valid base TOML");
    assert!(validate_profile_table(&parsed_valid).errors.is_empty());

    // 1. Mutate strip = "none"
    let unstripped: toml::Table = valid_base
        .replace("strip = \"symbols\"", "strip = \"none\"")
        .parse()
        .unwrap();
    let res = validate_profile_table(&unstripped);
    assert!(res
        .errors
        .iter()
        .any(|e| e.contains("strip must be \"symbols\"")));

    // 2. Mutate debug = true (DWARF debuginfo bloat)
    let debug_bloat: toml::Table = valid_base
        .replace("debug = false", "debug = true")
        .parse()
        .unwrap();
    let res = validate_profile_table(&debug_bloat);
    assert!(res.errors.iter().any(|e| e.contains("debug must be false")));

    // 3. Mutate panic = "abort"
    let abort_panic: toml::Table = valid_base
        .replace("panic = \"unwind\"", "panic = \"abort\"")
        .parse()
        .unwrap();
    let res = validate_profile_table(&abort_panic);
    assert!(res
        .errors
        .iter()
        .any(|e| e.contains("panic must be \"unwind\"")));

    // 4. Mutate overflow-checks = false
    let no_overflow: toml::Table = valid_base
        .replace("overflow-checks = true", "overflow-checks = false")
        .parse()
        .unwrap();
    let res = validate_profile_table(&no_overflow);
    assert!(res
        .errors
        .iter()
        .any(|e| e.contains("overflow-checks must be true")));

    // 5. Mutate opt-level = 2
    let low_opt: toml::Table = valid_base
        .replace("opt-level = 3", "opt-level = 2")
        .parse()
        .unwrap();
    let res = validate_profile_table(&low_opt);
    assert!(res.errors.iter().any(|e| e.contains("opt-level must be 3")));

    // 6. Mutate lto = "thin" in release
    let thin_lto: toml::Table = valid_base
        .replace("lto = \"fat\"", "lto = \"thin\"")
        .parse()
        .unwrap();
    let res = validate_profile_table(&thin_lto);
    assert!(res.errors.iter().any(|e| e.contains("lto must be \"fat\"")));

    // 7. Mutate codegen-units = 16 in release
    let many_cgu: toml::Table = valid_base
        .replace("\ncodegen-units = 1\n", "\ncodegen-units = 16\n")
        .parse()
        .unwrap();
    let res = validate_profile_table(&many_cgu);
    assert!(res
        .errors
        .iter()
        .any(|e| e.contains("codegen-units must be 1")));
    // 8. Novel unclassified profile key fails closed
    let unclassified: toml::Table = valid_base
        .replace(
            "[profile.release]",
            "[profile.release]\nunknown-experimental-profile-key = true",
        )
        .parse()
        .unwrap();
    let res = validate_profile_table(&unclassified);
    assert!(res.errors.iter().any(|e| e.contains("Unclassified key")));
}

#[test]
fn regression_row_139_binary_stripping_and_dwarf_bloat_detection() {
    // 1. Synthetic stripped ELF binary must pass validation
    let stripped_elf = build_synthetic_elf(false, false);
    let check_clean = validate_stripped_binary_bytes(&stripped_elf);
    assert!(
        check_clean.is_ok(),
        "Synthetic stripped ELF must pass validation: {:?}",
        check_clean
    );

    // 2. Synthetic ELF carrying .debug_info DWARF section must be rejected
    let dwarf_bloated_elf = build_synthetic_elf(true, false);
    let check_dwarf = validate_stripped_binary_bytes(&dwarf_bloated_elf);
    assert!(
        check_dwarf.is_err(),
        "ELF with .debug_info section must fail strip validation"
    );
    let errs = check_dwarf.unwrap_err();
    assert!(
        errs.iter().any(|e| e.contains(".debug_info")),
        "Error must name .debug_info section, got: {errs:?}"
    );

    // 3. Synthetic ELF carrying unstripped .symtab static symbol table must be rejected
    let symtab_bloated_elf = build_synthetic_elf(false, true);
    let check_symtab = validate_stripped_binary_bytes(&symtab_bloated_elf);
    assert!(
        check_symtab.is_err(),
        "ELF with .symtab section must fail strip validation"
    );
    let errs = check_symtab.unwrap_err();
    assert!(
        errs.iter().any(|e| e.contains(".symtab")),
        "Error must name .symtab section, got: {errs:?}"
    );

    // 4. Validate built release binary if present or required
    let mut candidate_paths = Vec::new();
    if let Some(explicit) = std::env::var_os("KEYHOG_RELEASE_BIN") {
        candidate_paths.push(PathBuf::from(explicit));
    }
    candidate_paths
        .push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/release/keyhog"));
    candidate_paths
        .push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/release/keyhog.exe"));
    candidate_paths
        .push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/release-fast/keyhog"));
    candidate_paths.push(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/release-fast/keyhog.exe"),
    );
    if let Some(target_dir) =
        std::env::var_os("CARGO_TARGET_DIR").or_else(|| std::env::var_os("CARGO_BUILD_TARGET_DIR"))
    {
        let p_rel = PathBuf::from(&target_dir).join("release");
        candidate_paths.push(p_rel.join("keyhog"));
        candidate_paths.push(p_rel.join("keyhog.exe"));
        let p_fast = PathBuf::from(&target_dir).join("release-fast");
        candidate_paths.push(p_fast.join("keyhog"));
        candidate_paths.push(p_fast.join("keyhog.exe"));
    }

    let mut validated_any = false;
    for path in &candidate_paths {
        if path.is_file() {
            let bytes = std::fs::read(path).expect("read existing release binary");
            let result = validate_stripped_binary_bytes(&bytes);
            assert!(
                result.is_ok(),
                "Existing release binary at {} failed strip/DWARF validation: {:?}",
                path.display(),
                result
            );
            validated_any = true;
        }
    }

    if std::env::var_os("KEYHOG_REQUIRE_RELEASE_BINARY").is_some() && !validated_any {
        panic!(
            "KEYHOG_REQUIRE_RELEASE_BINARY is set but no release binary was found in candidates: {:?}",
            candidate_paths
        );
    }
}
