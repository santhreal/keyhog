"""Single Python owner for detector TOML policy resolution in the ML pipeline."""

from __future__ import annotations

import tomllib
from pathlib import Path

DETECTORS_DIR = Path(__file__).resolve().parents[1] / "detectors"
_BY_ID: dict[str, dict] | None = None
_FALLBACK_OWNER: dict[str, dict] | None = None


def _load() -> tuple[dict[str, dict], dict[str, dict]]:
    global _BY_ID, _FALLBACK_OWNER
    if _BY_ID is None or _FALLBACK_OWNER is None:
        by_id: dict[str, dict] = {}
        fallback_owner: dict[str, dict] = {}
        for path in sorted(DETECTORS_DIR.glob("*.toml")):
            with path.open("rb") as fh:
                detector = tomllib.load(fh)["detector"]
            by_id[detector["id"]] = detector
            fallback = detector.get("entropy_fallback")
            if isinstance(fallback, dict):
                fallback_owner[fallback["id"]] = detector
        _BY_ID, _FALLBACK_OWNER = by_id, fallback_owner
    return _BY_ID, _FALLBACK_OWNER


def finding_base_id(detector_id: str) -> str:
    return detector_id.split(":", 1)[0]


def resolve_detector(detector_id: str) -> dict:
    by_id, fallback_owner = _load()
    finding_id = finding_base_id(detector_id)
    detector = by_id.get(finding_id) or fallback_owner.get(finding_id)
    if detector is None:
        raise ValueError(f"unknown detector or entropy owner {detector_id!r}")
    return detector


def candidate_channel(detector_id: str) -> str:
    _, fallback_owner = _load()
    return "entropy" if finding_base_id(detector_id) in fallback_owner else "pattern"


def validate_candidate_channel(detector_id: str, channel: str) -> dict:
    """Resolve provenance and reject train/serve channel skew."""
    detector = resolve_detector(detector_id)
    expected = candidate_channel(detector_id)
    if channel != expected:
        raise ValueError(
            f"detector {detector_id!r} requires candidate_channel={expected!r}, "
            f"got {channel!r}"
        )
    return detector


def model_mode(detector_id: str) -> str:
    detector = resolve_detector(detector_id)
    channel = candidate_channel(detector_id)
    field = "entropy_mode" if channel == "entropy" else "match_mode"
    return detector["ml"][field]


def model_can_reduce_recall(detector_id: str) -> bool:
    return model_mode(detector_id) in {"blend", "authoritative"}


def recall_sensitive_finding_ids() -> set[str]:
    """Finding identities whose model policy can suppress a real candidate."""
    by_id, _ = _load()
    identities: set[str] = set()
    for detector in by_id.values():
        ml = detector["ml"]
        if ml["match_mode"] in {"blend", "authoritative"}:
            identities.add(detector["id"])
        if ml["entropy_mode"] in {"blend", "authoritative"}:
            fallback = detector.get("entropy_fallback")
            if not isinstance(fallback, dict) or not fallback.get("id"):
                raise ValueError(
                    f"detector {detector['id']!r} has recall-sensitive entropy ML "
                    "policy without entropy_fallback identity"
                )
            identities.add(fallback["id"])
    return identities
