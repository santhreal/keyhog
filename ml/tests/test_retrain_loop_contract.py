from pathlib import Path
import shlex
import subprocess


def _resolver_section() -> str:
    script = Path("ml/retrain_loop.sh").read_text(encoding="utf-8")
    return script.split("# 1) Resolve", 1)[1].split("# 2) Harvest", 1)[0]


def test_retrain_loop_rebuilds_current_tree_instead_of_stale_binary_fallback():
    resolver = _resolver_section()

    assert "rebuilding current keyhog for harvest" in resolver
    assert "KEYHOG_VERSION" in resolver
    assert "harvest rebuild failed" in resolver
    for stale_probe in [
        "release-fast/keyhog",
        "release/keyhog",
        "command -v keyhog",
    ]:
        assert stale_probe not in resolver


def test_retrain_loop_restore_is_atomic_across_complete_serving_set(tmp_path):
    script = Path("ml/retrain_loop.sh").read_text(encoding="utf-8")
    restore_body = script.split("_restore_and_rebuild() {", 1)[1].split(
        "# 1) Resolve", 1
    )[0]
    restore_function = f"_restore_and_rebuild() {{{restore_body}"
    paths = {
        "WEIGHTS": tmp_path / "weights.bin",
        "QUANTIZED_MODEL": tmp_path / "quantized_moe.bin",
        "MODEL_CARD": tmp_path / "model_card.json",
    }

    def invoke_restore() -> subprocess.CompletedProcess[str]:
        assignments = "\n".join(
            f"{name}={shlex.quote(str(path))}" for name, path in paths.items()
        )
        return subprocess.run(
            [
                "bash",
                "-c",
                f"{assignments}\n_rebuild() {{ :; }}\n{restore_function}\n_restore_and_rebuild",
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    for path in paths.values():
        path.write_text(f"candidate:{path.name}", encoding="utf-8")
        Path(f"{path}.bak").write_text(f"accepted:{path.name}", encoding="utf-8")
    restored = invoke_restore()
    assert restored.returncode == 0, restored.stderr
    for path in paths.values():
        assert path.read_text(encoding="utf-8") == f"accepted:{path.name}"

    for path in paths.values():
        path.write_text(f"candidate:{path.name}", encoding="utf-8")
    Path(f"{paths['QUANTIZED_MODEL']}.bak").unlink()
    refused = invoke_restore()
    assert refused.returncode != 0
    assert "refusing a mixed model state" in refused.stderr
    for path in paths.values():
        assert path.read_text(encoding="utf-8") == f"candidate:{path.name}"
