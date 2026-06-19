from pathlib import Path


def _remote_driver_section() -> str:
    script = Path("benchmarks/cross_device.sh").read_text(encoding="utf-8")
    return script.split("# 1. keyhog:", 1)[1].split("# 2. corpus", 1)[0]


def test_cross_device_installs_current_repo_instead_of_path_keyhog():
    remote_driver = _remote_driver_section()

    assert "cargo install --path crates/cli" in remote_driver
    assert "KEYHOG_INSTALL_FEATURES" in remote_driver
    assert "command -v keyhog" not in remote_driver
