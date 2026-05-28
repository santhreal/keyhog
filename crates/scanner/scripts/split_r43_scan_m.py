#!/usr/bin/env python3
"""Split scanner src files that exceed the 500 LOC cap (R4.3-SCAN-M)."""

from pathlib import Path

ROOT = Path("/mnt/santh-desktop/software/keyhog/crates/scanner/src")


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    n = content.count("\n") + (0 if content.endswith("\n") else 1)
    print(f"wrote {path.relative_to(ROOT.parent.parent.parent)} ({n} lines)")


def split_engine_scan() -> None:
    src = (ROOT / "engine/scan.rs").read_text(encoding="utf-8")
    lines = src.splitlines(keepends=True)
    header = "".join(lines[:7])

    coalesced = header + "".join(lines[7:296])
    extract = header + "".join(lines[48:61]) + "".join(lines[297:])

    write(ROOT / "engine/scan.rs", "mod scan_coalesced;\nmod scan_extract;\n")
    write(ROOT / "engine/scan_coalesced.rs", coalesced)
    write(ROOT / "engine/scan_extract.rs", extract)


def split_engine_backend() -> None:
    src = (ROOT / "engine/backend.rs").read_text(encoding="utf-8")
    lines = src.splitlines(keepends=True)

    prepared = "".join(lines[:90])
    dispatch = (
        "use super::*;\nuse crate::context;\nuse crate::hw_probe::ScanBackend;\nuse keyhog_core::Chunk;\n\n"
        + "".join(lines[91:217])
    )
    pattern_hits = (
        "use super::*;\nuse crate::context;\nuse keyhog_core::RawMatch;\n\n"
        + "".join(lines[217:497])
    )
    triggered = (
        "use super::*;\nuse crate::hw_probe::ScanBackend;\nuse keyhog_core::RawMatch;\nuse vyre_libs::scan::LiteralMatch;\n\n"
        + "".join(lines[497:])
    )

    write(
        ROOT / "engine/backend.rs",
        "mod backend_dispatch;\nmod backend_pattern_hits;\nmod backend_prepared;\nmod backend_triggered;\n",
    )
    write(ROOT / "engine/backend_prepared.rs", prepared)
    write(ROOT / "engine/backend_dispatch.rs", dispatch)
    write(ROOT / "engine/backend_pattern_hits.rs", pattern_hits)
    write(ROOT / "engine/backend_triggered.rs", triggered)


def split_suppression() -> None:
    src = (ROOT / "pipeline/postprocess/suppression.rs").read_text(encoding="utf-8")
    lines = src.splitlines(keepends=True)

    helpers = "".join(lines[:134])
    marker_body = "".join(lines[146:306])  # inside should_suppress_inner, after locals
    tail_body = "".join(lines[307:658])  # rest of inner before closing brace
    b64 = "".join(lines[661:709])
    public = "".join(lines[32:107])

    markers = (
        "use crate::context;\nuse super::shape_gates::RFC7519_EXAMPLE_JWT_PREFIX;\nuse super::shape_gates::*;\nuse super::suppression_helpers::*;\n\n"
        + "pub(super) fn check_marker_and_prefix_gates(\n"
        + "    credential: &str,\n"
        + "    path: Option<&str>,\n"
        + "    upper: &str,\n"
        + "    bypass_shape_gates: bool,\n"
        + ") -> bool {\n"
        + marker_body
        + "}\n"
    )

    tail = (
        "use crate::context;\nuse super::shape_gates::*;\nuse super::suppression_b64::try_decode_b64_to_utf8;\nuse super::suppression_helpers::*;\n\n"
        + "pub(super) fn check_shape_context_and_b64_gates(\n"
        + "    credential: &str,\n"
        + "    path: Option<&str>,\n"
        + "    context: context::CodeContext,\n"
        + "    source_type: Option<&str>,\n"
        + "    upper: &str,\n"
        + "    skip_b64_decode_recheck: bool,\n"
        + "    bypass_shape_gates: bool,\n"
        + ") -> bool {\n"
        + tail_body
        + "}\n"
    )

    inner = (
        "use crate::context;\nuse super::suppression_helpers::*;\nuse super::suppression_markers::check_marker_and_prefix_gates;\n"
        + "use super::suppression_tail::check_shape_context_and_b64_gates;\n\n"
        + "pub(super) fn should_suppress_inner(\n"
        + "    credential: &str,\n"
        + "    path: Option<&str>,\n"
        + "    context: context::CodeContext,\n"
        + "    source_type: Option<&str>,\n"
        + "    skip_b64_decode_recheck: bool,\n"
        + "    bypass_shape_gates: bool,\n"
        + ") -> bool {\n"
        + "    let credential = suppression_credential_slice(credential);\n"
        + "    let upper = credential.to_uppercase();\n\n"
        + "    if check_marker_and_prefix_gates(credential, path, &upper, bypass_shape_gates) {\n"
        + "        return true;\n"
        + "    }\n"
        + "    check_shape_context_and_b64_gates(\n"
        + "        credential,\n"
        + "        path,\n"
        + "        context,\n"
        + "        source_type,\n"
        + "        &upper,\n"
        + "        skip_b64_decode_recheck,\n"
        + "        bypass_shape_gates,\n"
        + "    )\n"
        + "}\n"
    )

    suppression_rs = (
        "mod suppression_b64;\nmod suppression_helpers;\nmod suppression_inner;\nmod suppression_markers;\nmod suppression_tail;\n\n"
        + "use crate::context;\n\n"
        + public
    )

    write(ROOT / "pipeline/postprocess/suppression_helpers.rs", helpers)
    write(ROOT / "pipeline/postprocess/suppression_markers.rs", markers)
    write(ROOT / "pipeline/postprocess/suppression_tail.rs", tail)
    write(ROOT / "pipeline/postprocess/suppression_inner.rs", inner)
    write(ROOT / "pipeline/postprocess/suppression_b64.rs", b64)
    write(ROOT / "pipeline/postprocess/suppression.rs", suppression_rs)


def split_hw_probe() -> None:
    src = (ROOT / "hw_probe.rs").read_text(encoding="utf-8")
    lines = src.splitlines(keepends=True)
    write(ROOT / "hw_probe.rs", "".join(lines[:414]) + "\nmod hw_probe_platform;\n")
    write(ROOT / "hw_probe_platform.rs", "".join(lines[414:]))


def split_gpu() -> None:
    src = (ROOT / "gpu.rs").read_text(encoding="utf-8")
    lines = src.splitlines(keepends=True)
    backend_lines = lines[15:341]
    dedented = []
    for line in backend_lines:
        dedented.append(line[4:] if line.startswith("    ") else line)
    backend_mod = (
        "//! MoE GPU inference backend (wgpu compute).\n\nuse super::gpu_shader::MOE_SHADER;\n\n"
        + "".join(dedented)
    )
    public = "".join(lines[:14]) + "mod gpu_moe_backend;\n\n" + "".join(lines[341:])
    public = public.replace("backend::", "gpu_moe_backend::")
    write(ROOT / "gpu_moe_backend.rs", backend_mod)
    write(ROOT / "gpu.rs", public)


def split_compiler() -> None:
    src = (ROOT / "compiler.rs").read_text(encoding="utf-8")
    lines = src.splitlines(keepends=True)
    header = "".join(lines[:14])
    write(ROOT / "compiler_build.rs", header + "".join(lines[14:265]))
    write(ROOT / "compiler_compile.rs", header + "".join(lines[265:]))
    write(
        ROOT / "compiler.rs",
        header + "mod compiler_build;\nmod compiler_compile;\n\npub use compiler_build::*;\npub use compiler_compile::*;\n",
    )


def main() -> None:
    split_engine_scan()
    split_engine_backend()
    split_suppression()
    split_hw_probe()
    split_gpu()
    split_compiler()


if __name__ == "__main__":
    main()
