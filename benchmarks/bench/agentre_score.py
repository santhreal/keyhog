"""Fail-closed local reproduction of the pinned AgentRE-Bench scorer."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from pathlib import Path

STANDARD_WEIGHTS = {
    "decoded_c2": 0.40,
    "techniques": 0.30,
    "file_type": 0.10,
    "encoded_strings": 0.10,
    "c2_protocol": 0.10,
}
BONUS_WEIGHTS = {
    "decoded_c2": 0.15,
    "encryption_algorithm": 0.10,
    "encryption_key": 0.15,
    "encryption_key_storage": 0.05,
    "techniques": 0.15,
    "decoded_strings": 0.15,
    "anti_analysis": 0.10,
    "file_type": 0.03,
    "encoded_strings": 0.02,
    "c2_protocol": 0.05,
}
HALLUCINATION_PENALTY = 0.05
BONUS_HALLUCINATION_PENALTY = 0.03
BONUS_SAMPLE_PATTERN = re.compile(r"level(?:13|23)", re.IGNORECASE)


class AgentREScoreError(ValueError):
    """An AgentRE scoring input does not satisfy the pinned JSON contract."""


def _require_mapping(value: object, *, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise AgentREScoreError(f"AgentRE {context} must be a JSON object")
    if not all(isinstance(key, str) for key in value):
        raise AgentREScoreError(f"AgentRE {context} keys must be strings")
    return value


def _validate_optional_string(
    value: Mapping[str, object], field: str, *, required: bool, context: str
) -> None:
    if field not in value:
        if required:
            raise AgentREScoreError(f"AgentRE {context} is missing {field!r}")
        return
    observed = value[field]
    if observed is not None and not isinstance(observed, str):
        raise AgentREScoreError(
            f"AgentRE {context} field {field!r} must be a string or null"
        )


def _validate_exact_field(
    ground_truth: Mapping[str, object],
    agent: Mapping[str, object],
    field: str,
    expected_type: type,
) -> None:
    if field not in ground_truth or not isinstance(ground_truth[field], expected_type):
        raise AgentREScoreError(
            f"AgentRE ground truth field {field!r} must be {expected_type.__name__}"
        )
    if field in agent and not isinstance(agent[field], expected_type):
        raise AgentREScoreError(
            f"AgentRE agent field {field!r} must be {expected_type.__name__}"
        )


def _validate_string_list(
    value: Mapping[str, object], field: str, *, required: bool, context: str
) -> None:
    if field not in value:
        if required:
            raise AgentREScoreError(f"AgentRE {context} is missing {field!r}")
        return
    observed = value[field]
    if not isinstance(observed, list) or not all(
        isinstance(item, str) for item in observed
    ):
        raise AgentREScoreError(
            f"AgentRE {context} field {field!r} must be a list of strings"
        )


def _validate_standard_inputs(
    ground_truth: Mapping[str, object], agent: Mapping[str, object]
) -> None:
    _validate_optional_string(
        ground_truth, "decoded_c2", required=True, context="ground truth"
    )
    _validate_optional_string(agent, "decoded_c2", required=False, context="agent")
    _validate_string_list(
        ground_truth, "techniques", required=True, context="ground truth"
    )
    _validate_string_list(agent, "techniques", required=False, context="agent")
    _validate_exact_field(ground_truth, agent, "file_type", str)
    _validate_exact_field(ground_truth, agent, "encoded_strings", bool)
    _validate_exact_field(ground_truth, agent, "c2_protocol", str)


def _nested_mapping(
    value: Mapping[str, object], field: str, *, required: bool, context: str
) -> Mapping[str, object]:
    if field not in value:
        if required:
            raise AgentREScoreError(f"AgentRE {context} is missing {field!r}")
        return {}
    return _require_mapping(value[field], context=f"{context} field {field!r}")


def _validate_bonus_inputs(
    ground_truth: Mapping[str, object], agent: Mapping[str, object]
) -> None:
    _validate_standard_inputs(ground_truth, agent)
    gt_encryption = _nested_mapping(
        ground_truth, "encryption_details", required=True, context="ground truth"
    )
    agent_encryption = _nested_mapping(
        agent, "encryption_details", required=False, context="agent"
    )
    for field in ("algorithm", "key", "key_storage"):
        if field not in gt_encryption or not isinstance(gt_encryption[field], str):
            raise AgentREScoreError(
                f"AgentRE ground truth encryption field {field!r} must be str"
            )
        if field in agent_encryption and not isinstance(agent_encryption[field], str):
            raise AgentREScoreError(
                f"AgentRE agent encryption field {field!r} must be str"
            )

    gt_strings = _nested_mapping(
        ground_truth, "decoded_strings", required=True, context="ground truth"
    )
    agent_strings = _nested_mapping(
        agent, "decoded_strings", required=False, context="agent"
    )
    if not gt_strings or not all(
        isinstance(value, str) for value in gt_strings.values()
    ):
        raise AgentREScoreError(
            "AgentRE ground truth decoded_strings must contain string values"
        )
    if not all(isinstance(value, str) for value in agent_strings.values()):
        raise AgentREScoreError("AgentRE agent decoded_strings values must be strings")
    _validate_string_list(
        ground_truth, "anti_analysis", required=True, context="ground truth"
    )
    _validate_string_list(agent, "anti_analysis", required=False, context="agent")


def normalize_c2(value: str | None) -> str | None:
    """Apply the pinned scorer's decoded-C2 normalization."""

    if value is None:
        return None
    return value.strip().lower().rstrip("/")


def score_decoded_c2(ground_truth: str | None, agent: str | None) -> float:
    """Return exact credit, same-host partial credit, or zero."""

    expected = normalize_c2(ground_truth)
    observed = normalize_c2(agent)
    if expected == observed:
        return 1.0
    if expected is None or observed is None:
        return 0.0
    expected_host = expected.split("://")[-1].split("/")[0].split(":")[0]
    observed_host = observed.split("://")[-1].split("/")[0].split(":")[0]
    return 0.5 if expected_host == observed_host else 0.0


def score_set_overlap(
    ground_truth: Iterable[str] | None, agent: Iterable[str] | None
) -> tuple[float, int]:
    """Return pinned Jaccard credit and the distinct extra-claim count."""

    expected = set(ground_truth or [])
    observed = set(agent or [])
    if not expected and not observed:
        return 1.0, 0
    if not expected:
        return 0.0, len(observed)
    union = expected | observed
    return len(expected & observed) / len(union), len(observed - expected)


def score_exact(ground_truth: object, agent: object) -> float:
    """Apply the pinned exact scalar comparison."""

    if ground_truth is None and agent is None:
        return 1.0
    if isinstance(ground_truth, str) and isinstance(agent, str):
        return float(ground_truth.strip().lower() == agent.strip().lower())
    return float(ground_truth == agent)


def _base_result(tier: str) -> dict[str, object]:
    return {
        "tier": tier,
        "field_scores": {},
        "hallucinated_techniques": [],
        "missing_techniques": [],
        "hallucination_penalty": 0.0,
        "weighted_score": 0.0,
        "final_score": 0.0,
    }


def _finish_score(
    result: dict[str, object],
    weights: Mapping[str, float],
    hallucination_count: int,
    penalty_per_claim: float,
) -> dict[str, object]:
    field_scores = result["field_scores"]
    if not isinstance(field_scores, dict):
        raise AgentREScoreError("internal AgentRE field score state is invalid")
    weighted = sum(
        field_scores.get(field, 0.0) * weight for field, weight in weights.items()
    )
    penalty = penalty_per_claim * hallucination_count
    result["weighted_score"] = round(weighted, 4)
    result["hallucination_penalty"] = round(penalty, 4)
    result["final_score"] = round(max(0.0, weighted - penalty), 4)
    return result


def _result_fields(result: dict[str, object]) -> dict[str, float]:
    fields = result.get("field_scores")
    if not isinstance(fields, dict):
        raise AgentREScoreError("internal AgentRE field score state is invalid")
    return fields


def score_standard(
    ground_truth: Mapping[str, object], agent: Mapping[str, object]
) -> dict[str, object]:
    """Score one standard AgentRE level with the pinned rubric."""

    ground_truth = _require_mapping(ground_truth, context="ground truth")
    agent = _require_mapping(agent, context="agent output")
    _validate_standard_inputs(ground_truth, agent)
    result = _base_result("standard")
    fields = _result_fields(result)
    fields["decoded_c2"] = score_decoded_c2(
        ground_truth.get("decoded_c2"), agent.get("decoded_c2")
    )
    technique_score, extra_count = score_set_overlap(
        ground_truth.get("techniques"), agent.get("techniques")
    )
    fields["techniques"] = technique_score
    expected_techniques = set(ground_truth.get("techniques", []))
    observed_techniques = set(agent.get("techniques", []))
    result["hallucinated_techniques"] = sorted(
        observed_techniques - expected_techniques
    )
    result["missing_techniques"] = sorted(expected_techniques - observed_techniques)
    for field in ("file_type", "encoded_strings", "c2_protocol"):
        fields[field] = score_exact(ground_truth.get(field), agent.get(field))
    return _finish_score(result, STANDARD_WEIGHTS, extra_count, HALLUCINATION_PENALTY)


def score_bonus(
    ground_truth: Mapping[str, object], agent: Mapping[str, object]
) -> dict[str, object]:
    """Score one AgentRE bonus level with the pinned granular rubric."""

    ground_truth = _require_mapping(ground_truth, context="ground truth")
    agent = _require_mapping(agent, context="agent output")
    _validate_bonus_inputs(ground_truth, agent)
    result = _base_result("bonus")
    fields = _result_fields(result)
    fields["decoded_c2"] = score_decoded_c2(
        ground_truth.get("decoded_c2"), agent.get("decoded_c2")
    )
    gt_encryption = _nested_mapping(
        ground_truth, "encryption_details", required=True, context="ground truth"
    )
    agent_encryption = _nested_mapping(
        agent, "encryption_details", required=False, context="agent"
    )
    fields["encryption_algorithm"] = score_exact(
        gt_encryption.get("algorithm", ""), agent_encryption.get("algorithm", "")
    )
    fields["encryption_key"] = score_exact(
        gt_encryption.get("key", ""), agent_encryption.get("key", "")
    )
    gt_storage = str(gt_encryption.get("key_storage", "")).lower()
    agent_storage = str(agent_encryption.get("key_storage", "")).lower()
    storage_score = 0.0
    if gt_storage and agent_storage:
        storage_score += 0.5 if "xor" in agent_storage else 0.0
        storage_score += (
            0.5 if "0xa5" in agent_storage or "a5" in agent_storage else 0.0
        )
    elif not gt_storage and not agent_storage:
        storage_score = 1.0
    fields["encryption_key_storage"] = min(storage_score, 1.0)

    technique_score, extra_count = score_set_overlap(
        ground_truth.get("techniques"), agent.get("techniques")
    )
    fields["techniques"] = technique_score
    expected_techniques = set(ground_truth.get("techniques", []))
    observed_techniques = set(agent.get("techniques", []))
    result["hallucinated_techniques"] = sorted(
        observed_techniques - expected_techniques
    )
    result["missing_techniques"] = sorted(expected_techniques - observed_techniques)

    expected_strings = _nested_mapping(
        ground_truth, "decoded_strings", required=True, context="ground truth"
    )
    observed_strings = _nested_mapping(
        agent, "decoded_strings", required=False, context="agent"
    )
    matched_strings = sum(
        observed_strings.get(key) is not None
        and str(observed_strings[key]).strip() == str(value).strip()
        for key, value in expected_strings.items()
    )
    fields["decoded_strings"] = matched_strings / len(expected_strings)
    anti_analysis_score, _ = score_set_overlap(
        ground_truth.get("anti_analysis"), agent.get("anti_analysis")
    )
    fields["anti_analysis"] = anti_analysis_score
    for field in ("file_type", "encoded_strings", "c2_protocol"):
        fields[field] = score_exact(ground_truth.get(field), agent.get(field))
    return _finish_score(
        result, BONUS_WEIGHTS, extra_count, BONUS_HALLUCINATION_PENALTY
    )


def is_bonus(ground_truth: Mapping[str, object], ground_truth_path: str = "") -> bool:
    """Use the pinned scorer's level-13/23 sample identity dispatch."""

    sample = ground_truth.get("sample", "") or Path(ground_truth_path).stem
    if not isinstance(sample, str):
        raise AgentREScoreError("AgentRE ground truth sample must be a string")
    return BONUS_SAMPLE_PATTERN.search(sample) is not None


def score_sample(
    ground_truth: Mapping[str, object],
    agent: Mapping[str, object],
    ground_truth_path: str = "",
) -> dict[str, object]:
    """Dispatch one sample to the pinned standard or bonus rubric."""

    ground_truth = _require_mapping(ground_truth, context="ground truth")
    agent = _require_mapping(agent, context="agent output")
    if is_bonus(ground_truth, ground_truth_path):
        return score_bonus(ground_truth, agent)
    return score_standard(ground_truth, agent)


def score_report(
    samples: Iterable[tuple[Mapping[str, object], Mapping[str, object], str]],
) -> dict[str, object]:
    """Score samples and reproduce the pinned batch summary and grand total."""

    results: list[dict[str, object]] = []
    for ground_truth, agent, path in sorted(samples, key=lambda sample: sample[2]):
        ground_truth = _require_mapping(ground_truth, context="ground truth")
        result = score_sample(ground_truth, agent, path)
        sample = ground_truth.get("sample", Path(path).stem)
        if not isinstance(sample, str) or not sample:
            raise AgentREScoreError("AgentRE ground truth sample must be non-empty")
        result["sample"] = sample
        results.append(result)

    standard = [result for result in results if result["tier"] == "standard"]
    bonus = [result for result in results if result["tier"] == "bonus"]
    main_score = (
        sum(float(result["final_score"]) for result in standard) / len(standard)
        if standard
        else 0.0
    )
    bonus_score = float(bonus[0]["final_score"]) if bonus else 0.0
    summary = {
        "standard_samples": len(standard),
        "main_score": round(main_score, 4),
        "main_max": 1.0,
        "bonus_score": round(bonus_score, 4),
        "bonus_max": 1.0,
        "total_score": round(main_score + bonus_score, 4),
        "total_max": (1.0 if standard else 0.0) + (1.0 if bonus else 0.0),
        "standard_weights": STANDARD_WEIGHTS,
        "bonus_weights": BONUS_WEIGHTS,
        "hallucination_penalty_standard": HALLUCINATION_PENALTY,
        "hallucination_penalty_bonus": BONUS_HALLUCINATION_PENALTY,
    }
    return {"results": results, "summary": summary}
