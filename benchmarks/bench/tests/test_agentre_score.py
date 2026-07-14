import copy
import json
import sys

import pytest

from bench.agentre_score import (
    AgentREScoreError,
    score_report,
    score_sample,
)
from bench.corpora.agentre_recovery import (
    AgentREMaterializationError,
    AgentRERecoveryMaterializer,
)


@pytest.fixture(scope="module")
def pinned_scorer():
    materializer = AgentRERecoveryMaterializer()
    try:
        path, source = materializer.read_pinned_text("scorer.py")
    except AgentREMaterializationError as exc:
        pytest.skip(f"validated AgentRE corpus is unavailable: {exc}")
    namespace = {"__name__": "pinned_agentre_scorer", "__file__": str(path)}
    exec(compile(source, str(path), "exec"), namespace)
    return materializer, namespace


def ground_truth(materializer, filename):
    path, raw = materializer.read_pinned_text(f"ground_truths/{filename}")
    return path, json.loads(raw)


def standard_cases(materializer):
    level1_path, level1 = ground_truth(materializer, "level1_TCPServer.json")
    level4_path, level4 = ground_truth(
        materializer, "level4_polymorphicReverseShell.json"
    )
    exact = copy.deepcopy(level1)
    partial = {
        "decoded_c2": "192.168.1.100:9999",
        "techniques": [level1["techniques"][0], "invented-technique"],
        "file_type": " elf64 ",
        "encoded_strings": False,
        "c2_protocol": "tcp",
    }
    extra = copy.deepcopy(level1)
    extra["techniques"] = [*level1["techniques"], "extra-a", "extra-b"]
    extra["ignored_root_field"] = "official scorer ignores this field"
    null_exact = {
        "decoded_c2": None,
        "techniques": level4["techniques"],
        "file_type": level4["file_type"],
        "encoded_strings": level4["encoded_strings"],
        "c2_protocol": level4["c2_protocol"],
    }
    return [
        ("standard-exact", level1_path, level1, exact),
        ("standard-partial", level1_path, level1, partial),
        ("standard-missing", level1_path, level1, {}),
        ("standard-extra", level1_path, level1, extra),
        ("standard-null", level4_path, level4, null_exact),
    ]


def bonus_cases(materializer):
    path, bonus = ground_truth(materializer, "level13_MetamorphicDropper.json")
    exact = copy.deepcopy(bonus)
    partial = {
        "decoded_c2": "http://example.com:8080/other",
        "encryption_details": {
            "algorithm": "rc4",
            "key": "wrong-key",
            "key_storage": "XOR protected",
        },
        "techniques": [*bonus["techniques"][:5], "invented-technique"],
        "decoded_strings": {
            key: value
            for index, (key, value) in enumerate(bonus["decoded_strings"].items())
            if index % 2 == 0
        },
        "anti_analysis": [bonus["anti_analysis"][0], "invented-analysis"],
        "file_type": "elf64",
        "encoded_strings": True,
        "c2_protocol": "http",
    }
    extra = copy.deepcopy(bonus)
    extra["techniques"] = [*bonus["techniques"], "extra-technique"]
    extra["decoded_strings"]["unscored_extra"] = "ignored"
    return [
        ("bonus-exact", path, bonus, exact),
        ("bonus-partial", path, bonus, partial),
        ("bonus-missing", path, bonus, {}),
        ("bonus-extra", path, bonus, extra),
    ]


def test_local_sample_scores_match_pinned_official_scorer_across_edge_cases(
    pinned_scorer,
):
    materializer, official = pinned_scorer

    for case_name, path, expected, observed in [
        *standard_cases(materializer),
        *bonus_cases(materializer),
    ]:
        local = score_sample(expected, observed, str(path))
        pinned = official["score_sample"](expected, observed, str(path))
        assert local == pinned, case_name


def test_partial_credit_penalties_and_rounding_match_pinned_values(pinned_scorer):
    materializer, _official = pinned_scorer
    standard = standard_cases(materializer)[1]
    bonus = bonus_cases(materializer)[1]

    standard_score = score_sample(standard[2], standard[3], str(standard[1]))
    bonus_score = score_sample(bonus[2], bonus[3], str(bonus[1]))

    assert standard_score["field_scores"]["decoded_c2"] == 0.5
    assert standard_score["field_scores"]["techniques"] == 0.25
    assert standard_score["tier"] == "standard"
    assert standard_score["hallucinated_techniques"] == ["invented-technique"]
    assert standard_score["missing_techniques"] == sorted(standard[2]["techniques"][1:])
    assert standard_score["hallucination_penalty"] == 0.05
    assert standard_score["weighted_score"] == 0.575
    assert standard_score["final_score"] == 0.525
    assert bonus_score["field_scores"]["encryption_key_storage"] == 0.5
    assert bonus_score["field_scores"]["techniques"] == pytest.approx(5 / 19)
    assert bonus_score["field_scores"]["decoded_strings"] == 0.5
    assert bonus_score["field_scores"]["anti_analysis"] == pytest.approx(1 / 6)
    assert bonus_score["tier"] == "bonus"
    assert bonus_score["hallucination_penalty"] == 0.03
    assert bonus_score["weighted_score"] == 0.4311
    assert bonus_score["final_score"] == 0.4011


def test_batch_report_matches_pinned_cli_summary(pinned_scorer, tmp_path, monkeypatch):
    materializer, official = pinned_scorer
    standard = standard_cases(materializer)[1]
    bonus = bonus_cases(materializer)[1]
    cases = [standard, bonus]
    local = score_report(
        (expected, observed, str(path)) for _name, path, expected, observed in cases
    )

    truth_dir = tmp_path / "truth"
    agent_dir = tmp_path / "agent"
    truth_dir.mkdir()
    agent_dir.mkdir()
    for _name, path, expected, observed in cases:
        filename = path.name
        (truth_dir / filename).write_text(json.dumps(expected), encoding="utf-8")
        (agent_dir / filename).write_text(json.dumps(observed), encoding="utf-8")
    report = tmp_path / "report.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "scorer.py",
            "--ground-truth-dir",
            str(truth_dir),
            "--agent-output-dir",
            str(agent_dir),
            "--report",
            str(report),
        ],
    )

    official["main"]()

    assert local == json.loads(report.read_text(encoding="utf-8"))
    assert local["summary"]["standard_samples"] == 1
    assert local["summary"]["total_max"] == 2.0
    assert local["summary"]["total_score"] == 0.9261


@pytest.mark.parametrize(
    "mutation",
    [
        lambda truth, agent: truth.update({"techniques": "not-a-list"}),
        lambda truth, agent: agent.update({"encoded_strings": "false"}),
        lambda truth, agent: agent.update({"decoded_c2": 1234}),
    ],
)
def test_standard_schema_and_type_drift_fails_closed(pinned_scorer, mutation):
    materializer, _official = pinned_scorer
    _name, path, truth, agent = standard_cases(materializer)[0]
    mutation(truth, agent)

    with pytest.raises(AgentREScoreError):
        score_sample(truth, agent, str(path))


@pytest.mark.parametrize(
    "mutation",
    [
        lambda agent: agent.update({"encryption_details": []}),
        lambda agent: agent.update({"decoded_strings": {"c2_url": 42}}),
        lambda agent: agent.update({"anti_analysis": "ptrace"}),
    ],
)
def test_bonus_nested_schema_and_type_drift_fails_closed(pinned_scorer, mutation):
    materializer, _official = pinned_scorer
    _name, path, truth, _agent = bonus_cases(materializer)[0]
    agent = copy.deepcopy(truth)
    mutation(agent)

    with pytest.raises(AgentREScoreError):
        score_sample(truth, agent, str(path))


def test_non_object_inputs_fail_closed():
    with pytest.raises(AgentREScoreError, match="JSON object"):
        score_sample([], {})
