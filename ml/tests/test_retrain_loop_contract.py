from pathlib import Path


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
