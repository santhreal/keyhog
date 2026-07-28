"""Behavioral tests for the fail-closed hosted CPU evidence boundary.

Fixtures are persisted result JSON; the gate never reruns or repairs a scanner.
Each regression test names the historical false-pass/crash class it prevents.
"""

from __future__ import annotations

import copy
import hashlib
import json
import pathlib
from datetime import datetime, timezone

import pytest

from bench import hosted_cpu_gate as hosted_gate

from bench.hosted_cpu_gate import (
    CONTEXT_SCHEMA,
    PARITY_SCHEMA,
    TrustedRun,
    load_policy,
    policy_sha256,
    run_gate,
    validate_evidence,
)
from bench.schema import (
    CorpusInfo,
    Detection,
    Host,
    HostedBinding,
    Outcome,
    RunResult,
    Scanner,
    ScannerConfig,
    Speed,
    StaticRecoveryMetrics,
)

_POLICY = pathlib.Path(__file__).resolve().parents[2] / "cpu-gates" / "github-ubuntu-24.04-4core-nightly.json"
_COMMIT = "a" * 40
_BINARY_SHA = "b" * 64
_DETECTOR_SHA = "c" * 64
_CONTEXT_TIME = "2026-07-27T10:00:00+00:00"
_ROW_TIME = "2026-07-27T10:01:00+00:00"
_NOW = datetime(2026, 7, 27, 10, 5, tzinfo=timezone.utc)
_REPOSITORY = "santhreal/keyhog"
_WORKFLOW_REF = "santhreal/keyhog/.github/workflows/bench-nightly.yml@refs/heads/main"


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _manifest(mode: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "preset": "default",
        "effective": {
            "backend": "simd",
            "decode_depth": {"fast": "2", "full": "10", "deep": "20", "precision": "10"}[mode],
            "confidence_policy": "compiled-default",
        },
        "overrides": [],
    }


def _calibrated_policy(tmp_path: pathlib.Path):
    raw = json.loads(_POLICY.read_text())
    raw["workloads"]["creddata"].update(
        fixture_count=65708,
        bytes=1_000_000_000,
        workload_sha256="e" * 64,
    )
    raw["supply"]["runner_image_version"] = "20260720.1.0"
    raw["supply"]["libhs_runtime_sha256"] = "3" * 64
    for row in raw["rows"]:
        row["scan_manifest_sha256"] = _canonical_sha(_manifest(row["config"]["mode"]))
    path = tmp_path / "policy.json"
    path.write_bytes(_json_bytes(raw))
    return path, load_policy(path)


def _host() -> Host:
    return Host(
        hostname_hash="012345abcdef",
        os="Linux 6.11.0",
        kernel="#1 SMP",
        cpu="GitHub Actions 4-core CPU",
        cores=4,
        affinity_cores=4,
        cgroup_quota_cores=4.0,
        ram_mb=16000,
        gpu="",
        gpu_vram_mb=0,
    )


def _context(policy_path: pathlib.Path, policy) -> dict[str, object]:
    workloads = {
        name: CorpusInfo(
            name=name,
            fixture_count=item.fixture_count or 1,
            labeled_positives=item.labeled_positives,
            bytes=item.bytes or 1,
            workload_sha256=item.workload_sha256 or "9" * 64,
        ).to_json()
        for name, item in policy.workloads.items()
    }
    category_denominators = {}
    for name, workload in policy.workloads.items():
        policy_categories = next(
            (
                row.categories
                for row in policy.rows
                if row.corpus == name and row.categories
            ),
            (),
        )
        category_denominators[name] = (
            {category.name: category.positives for category in policy_categories}
            if policy_categories
            else {"api": workload.labeled_positives}
        )
    return {
        "schema_version": CONTEXT_SCHEMA,
        "generated_at": _CONTEXT_TIME,
        "policy_sha256": policy_sha256(policy_path),
        "source_commit": _COMMIT,
        "executable_sha256": _BINARY_SHA,
        "detector_corpus_sha256": _DETECTOR_SHA,
        "runner": {
            "provider": "github-actions",
            "profile": policy.profile,
            "name": "GitHub Actions 7",
            "os": policy.runner_os,
            "arch": policy.runner_arch,
            "environment": policy.runner_environment,
            "workflow": policy.workflow,
            "workflow_ref": _WORKFLOW_REF,
            "workflow_sha": _COMMIT,
            "repository": _REPOSITORY,
            "run_id": "1234",
            "run_attempt": "1",
            "job": "leaderboard",
        },
        "host": _host().to_json(),
        "accelerator_enforcement": {
            "cuda_visible_devices": "",
            "nvidia_visible_devices": "void",
            "route": "policy-cpu-simd-only",
            "inventory": {
                "source": "nvidia-smi",
                "status": "nvidia-smi-unavailable",
                "devices": [],
            },
        },
        "workloads": workloads,
        "category_denominators": category_denominators,
        "supply": {
            "schema_version": "hosted-cpu-supply-v1",
            "runner_image": {
                "label": "ubuntu-24.04",
                "os": "ubuntu24",
                "version": "20260720.1.0",
            },
            "cpython": {"requested": "3.12.11", "observed": "3.12.11"},
            "go": {"requested": "1.22.2", "observed": "1.22.2"},
            "apt": {
                "libhyperscan-dev": "5.4.2-2",
                "libhyperscan5": "5.4.2-2",
                "pkg-config": "1.8.1-2build1",
            },
            "libhs_runtime": {
                "path": "/usr/lib/x86_64-linux-gnu/libhs.so.5",
                "sha256": "3" * 64,
                "package": "libhyperscan5",
                "package_version": "5.4.2-2",
            },
        },
        "immutability": {
            "schema_version": "hosted-cpu-immutability-v1",
            "snapshot_root": "/tmp/keyhog-hosted-snapshot",
            "owner": "root:root",
            "mount_options": ["bind", "ro"],
            "write_probe": "rejected",
            "interval_end": "post-publication cleanup",
        },
        "snapshot_roots": {
            name: f"/tmp/keyhog-hosted-snapshot/{name}" for name in workloads
        },
        "acquisition": {
            name: {
                "revision": policy.workloads[name].revision,
                "source_root_sha256": value["workload_sha256"],
                "snapshot_root_sha256": value["workload_sha256"],
            }
            for name, value in workloads.items()
        },
    }


def _trusted(policy_path: pathlib.Path) -> TrustedRun:
    return TrustedRun(
        now=_NOW,
        policy_sha256=policy_sha256(policy_path),
        repository=_REPOSITORY,
        workflow_ref=_WORKFLOW_REF,
        workflow_sha=_COMMIT,
        run_id="1234",
        run_attempt="1",
        job="leaderboard",
    )


def _parity(policy, context: dict[str, object], context_sha: str) -> dict[str, object]:
    return {
        "schema_version": PARITY_SCHEMA,
        "generated_at": _ROW_TIME,
        "source_commit": _COMMIT,
        "detector_corpus_sha256": _DETECTOR_SHA,
        "policy_sha256": context["policy_sha256"],
        "context_sha256": context_sha,
        "repository": _REPOSITORY,
        "workflow_ref": _WORKFLOW_REF,
        "workflow_sha": _COMMIT,
        "run_id": "1234",
        "run_attempt": "1",
        "job": "leaderboard",
        "release_executable_sha256": _BINARY_SHA,
        "test_executable_sha256": hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
        "parity_source_sha256": policy.parity_source_sha256,
        "vector_sha256": policy.parity_vector_sha256,
        "detector_examples": policy.parity_detector_examples,
        "unicode_divergences": 0,
        "command": [str(pathlib.Path(__file__).resolve()), "--nocapture"],
    }


def _row(requirement, context, context_sha: str) -> RunResult:
    corpus = CorpusInfo.from_json(context["workloads"][requirement.corpus])
    categories = {
        name: Outcome(tp=positives)
        for name, positives in context["category_denominators"][
            requirement.corpus
        ].items()
    }
    wall_ms = min(
        requirement.max_wall_ms / 2,
        (corpus.bytes / 1_048_576.0) / (requirement.min_throughput_mib_s * 2) * 1000,
    )
    throughput = (corpus.bytes / 1_048_576.0) / (wall_ms / 1000.0)
    return RunResult(
        generated_at=_ROW_TIME,
        host=_host(),
        scanner=Scanner(
            name="keyhog",
            version=f"keyhog 0.6.0\nCommit: {_COMMIT}\nDetector Set: 848",
            config=ScannerConfig(**requirement.config),
            executable_sha256=_BINARY_SHA,
            detector_corpus_sha256=_DETECTOR_SHA,
            execution_route="in_process",
        ),
        corpus=corpus,
        detection=Detection(
            overall=Outcome(tp=corpus.labeled_positives),
            per_category=categories,
        ),
        speed=Speed(
            wall_ms=wall_ms,
            throughput_mb_s=throughput,
            peak_rss_kb=requirement.max_peak_rss_kb // 2,
        ),
        finding_count=corpus.labeled_positives,
        exit_code=1,
        scan_manifest=_manifest(requirement.config["mode"]),
        static_recovery=StaticRecoveryMetrics(),
        hosted_binding=HostedBinding(
            context_sha256=context_sha,
            repository=_REPOSITORY,
            workflow_ref=_WORKFLOW_REF,
            workflow_sha=_COMMIT,
            run_id="1234",
            run_attempt="1",
            job="leaderboard",
        ),
    )


def _write_rows(root: pathlib.Path, policy, context, context_sha: str) -> dict[str, dict]:
    rows: dict[str, dict] = {}
    for requirement in policy.rows:
        value = _row(requirement, context, context_sha).to_json()
        path = root / requirement.path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_json_bytes(value))
        rows[requirement.id] = value
    return rows


def _rewrite(root: pathlib.Path, policy, row_id: str, value: dict) -> None:
    requirement = next(item for item in policy.rows if item.id == row_id)
    (root / requirement.path).write_bytes(_json_bytes(value))


def _rebind_context(evidence) -> None:
    context_sha = hashlib.sha256(_json_bytes(evidence["context"])).hexdigest()
    evidence["parity"]["context_sha256"] = context_sha
    for row_id, row in evidence["rows"].items():
        row["host"] = copy.deepcopy(evidence["context"]["host"])
        row["hosted_binding"]["context_sha256"] = context_sha
        _rewrite(evidence["root"], evidence["policy"], row_id, row)


@pytest.fixture
def evidence(tmp_path):
    policy_path, policy = _calibrated_policy(tmp_path)
    context = _context(policy_path, policy)
    context_sha = hashlib.sha256(_json_bytes(context)).hexdigest()
    parity = _parity(policy, context, context_sha)
    rows = _write_rows(tmp_path, policy, context, context_sha)
    return {
        "policy_path": policy_path,
        "policy": policy,
        "context": context,
        "context_sha": context_sha,
        "parity": parity,
        "rows": rows,
        "root": tmp_path,
        "trusted": _trusted(policy_path),
    }


def _violations(evidence, *, policy_path=None, policy=None, trusted=None):
    return validate_evidence(
        policy or evidence["policy"],
        policy_path or evidence["policy_path"],
        evidence["context"],
        evidence["parity"],
        evidence["root"],
        trusted=trusted or evidence["trusted"],
        context_sha256=hashlib.sha256(_json_bytes(evidence["context"])).hexdigest(),
    )


def test_valid_exact_hosted_cpu_evidence_passes_deterministically(evidence):
    """A complete current-run receipt passes twice; hidden reruns/state cannot alter verdicts."""
    assert _violations(evidence) == []
    assert _violations(evidence) == []


def test_self_authored_fresh_timestamp_cannot_replace_trusted_utc(evidence):
    """A stale bundle once refreshed its own clock and false-passed; trusted UTC now rejects it."""
    evidence["trusted"] = TrustedRun(
        **{**evidence["trusted"].__dict__, "now": datetime(2026, 7, 28, tzinfo=timezone.utc)}
    )
    assert any("stale relative to trusted" in item for item in _violations(evidence))


@pytest.mark.parametrize("field", ["repository", "workflow_ref", "workflow_sha", "run_id", "run_attempt", "job"])
def test_coordinated_receipt_rewrite_cannot_replace_trusted_run(evidence, field):
    """Rewriting context/parity/rows together once forged provenance; workflow inputs remain authoritative."""
    replacement = "999" if field in {"run_id", "run_attempt"} else ("d" * 40 if field == "workflow_sha" else "attacker/value")
    evidence["context"]["runner"][field] = replacement
    assert any(f"wrong trusted runner {field}" in item for item in _violations(evidence))


def test_arbitrary_policy_and_matching_context_cannot_replace_reviewed_digest(evidence, tmp_path):
    """A caller-selected weaker policy once governed itself; the workflow-pinned digest now wins."""
    raw = json.loads(evidence["policy_path"].read_text())
    raw["calibration"]["rationale"] = "attacker-selected policy"
    foreign = tmp_path / "foreign-policy.json"
    foreign.write_bytes(_json_bytes(raw))
    assert any("reviewed policy SHA-256" in item for item in _violations(
        evidence, policy_path=foreign, policy=load_policy(foreign)
    ))


def test_committed_uncalibrated_identity_pins_fail_closed(tmp_path):
    """Null workload/manifest/image/libhs pins once acted as wildcards; first hosted evidence stays red."""
    policy = load_policy(_POLICY)
    assert policy.workloads["creddata"].workload_sha256 is None
    assert all(row.scan_manifest_sha256 is None for row in policy.rows)
    assert policy.supply["runner_image_version"] is None
    assert policy.supply["libhs_runtime_sha256"] is None


def test_null_external_supply_pins_are_gate_violations(evidence, tmp_path):
    """Null image/libhs pins once behaved like wildcards; otherwise valid supply remains unpublishable."""
    raw = json.loads(evidence["policy_path"].read_text())
    raw["supply"]["runner_image_version"] = None
    raw["supply"]["libhs_runtime_sha256"] = None
    path = tmp_path / "unpinned-supply.json"
    path.write_bytes(_json_bytes(raw))
    violations = _violations(
        evidence,
        policy_path=path,
        policy=load_policy(path),
    )
    assert any("runner image version policy is uncalibrated" in item for item in violations)
    assert any("libhs runtime digest policy is uncalibrated" in item for item in violations)


def test_supply_versions_and_runtime_digest_are_policy_bound(evidence):
    """A mutable apt/runtime rollout once fit the same runner label; exact receipt substitution now fails."""
    evidence["context"]["supply"]["apt"]["libhyperscan5"] = "5.4.2-99"
    evidence["context"]["supply"]["libhs_runtime"]["sha256"] = "4" * 64
    violations = _violations(evidence)
    assert any("apt supply versions differ" in item for item in violations)


def test_immutability_receipt_requires_root_owned_read_only_mount(evidence):
    """chmod plus pre/post hashes once missed mutate-restore scans; missing VFS read-only proof fails closed."""
    evidence["context"]["immutability"]["owner"] = "runner:runner"
    evidence["context"]["immutability"]["mount_options"] = ["bind", "rw"]
    assert any(
        "snapshot interval is not root-owned read-only" in item
        for item in _violations(evidence)
    )


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("available",), 1, "available must be true"),
        (("timed_out",), 0, "timed_out must be false"),
        (("exit_code",), "1", "JSON integer"),
        (("finding_count",), True, "JSON integer"),
        (("corpus", "fixture_count"), "15000", "JSON integer"),
        (("detection", "overall", "tp"), True, "JSON integer"),
        (("speed", "peak_rss_kb"), 1.5, "JSON integer"),
        (("speed", "wall_ms"), float("nan"), "non-finite JSON"),
    ],
)
def test_json_scalar_coercions_and_nonfinite_numbers_fail_closed(evidence, path, value, message):
    """Python bool/int/string/NaN coercions once false-passed or crashed; raw JSON types are now exact."""
    row = evidence["rows"]["mirror"]
    target = row
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    _rewrite(evidence["root"], evidence["policy"], "mirror", row)
    assert any(message in item for item in _violations(evidence))


def test_success_exit_domain_is_exact(evidence):
    """Any nonnegative exit once counted as success; an unknown scanner exit now invalidates evidence."""
    evidence["rows"]["mirror"]["exit_code"] = 2
    _rewrite(evidence["root"], evidence["policy"], "mirror", evidence["rows"]["mirror"])
    assert any("not a KeyHog success" in item for item in _violations(evidence))


def test_complete_config_rejects_untracked_confidence_override(evidence):
    """A matching config_id once hid min_confidence overrides; complete effective axes must match policy."""
    evidence["rows"]["mirror"]["scanner"]["config"]["min_confidence"] = 0.01
    _rewrite(evidence["root"], evidence["policy"], "mirror", evidence["rows"]["mirror"])
    assert any("config keys differ" in item for item in _violations(evidence))


@pytest.mark.parametrize("mutation", ["missing", "effective", "preset"])
def test_complete_resolved_manifest_is_policy_pinned(evidence, mutation):
    """Mode labels once hid altered scan defaults; the full resolved manifest digest prevents false equivalence."""
    manifest = evidence["rows"]["mirror"]["scan_manifest"]
    if mutation == "missing":
        manifest.pop("effective")
    elif mutation == "effective":
        manifest["effective"]["decode_depth"] = "999"
    else:
        manifest["preset"] = "fast"
    _rewrite(evidence["root"], evidence["policy"], "mirror", evidence["rows"]["mirror"])
    assert any("manifest" in item for item in _violations(evidence))


def test_scan_preset_is_independent_from_validation_mode(evidence):
    """The CLI preset and benchmark validation mode are separate axes; valid full-mode default scans must pass."""
    row = evidence["rows"]["mirror"]
    assert row["scanner"]["config"]["mode"] == "full"
    assert row["scan_manifest"]["preset"] == "default"
    assert _violations(evidence) == []


def test_throughput_must_be_derived_from_bound_bytes_and_wall(evidence):
    """A self-reported throughput once passed independently; byte/wall recomputation catches forged units."""
    evidence["rows"]["mirror"]["speed"]["throughput_mb_s"] *= 2
    _rewrite(evidence["root"], evidence["policy"], "mirror", evidence["rows"]["mirror"])
    assert any("not derived" in item for item in _violations(evidence))


@pytest.mark.parametrize("field", ["wall_ms", "throughput_mb_s", "peak_rss_kb"])
def test_each_performance_limit_is_enforced(evidence, field):
    """Checking a single perf scalar once masked wall/throughput/RSS regressions; each unit has its own gate."""
    requirement = evidence["policy"].rows[0]
    value = {
        "wall_ms": requirement.max_wall_ms + 1,
        "throughput_mb_s": requirement.min_throughput_mib_s / 2,
        "peak_rss_kb": requirement.max_peak_rss_kb + 1,
    }[field]
    evidence["rows"]["mirror"]["speed"][field] = value
    _rewrite(evidence["root"], evidence["policy"], "mirror", evidence["rows"]["mirror"])
    assert _violations(evidence)


@pytest.mark.parametrize("field", ["cores", "affinity_cores", "cgroup_quota_cores"])
def test_exact_effective_four_core_class_rejects_other_allocations(evidence, field):
    """Broad logical-core ranges once admitted larger/oversubscribed hosts; allocation identity is exact."""
    evidence["context"]["host"][field] = 8
    assert any("host " in item for item in _violations(evidence))


@pytest.mark.parametrize("quota", ["missing", "unknown", 0.0])
def test_unproven_cgroup_quota_fails_the_hosted_gate(evidence, quota):
    """Missing, unobservable, and invalid quota evidence must all fail closed."""
    if quota == "missing":
        evidence["context"]["host"].pop("cgroup_quota_cores")
    else:
        evidence["context"]["host"]["cgroup_quota_cores"] = quota

    assert any(
        "cgroup quota" in item or "context host keys differ" in item
        for item in _violations(evidence)
    )


def test_capture_rejects_unknown_cgroup_quota_before_snapshotting(
    monkeypatch,
    tmp_path,
):
    """Hosted capture must stop when quota is unobservable, before producing consumable context."""
    policy_path, policy = _calibrated_policy(tmp_path)
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    binary = tmp_path / "keyhog"
    binary.write_bytes(b"release binary")
    host = _host()
    host.cgroup_quota_cores = "unknown"
    monkeypatch.setattr(hosted_gate, "workspace_git_hash", lambda root: _COMMIT)
    monkeypatch.setattr(
        hosted_gate,
        "assert_workspace_tracked_tree_clean",
        lambda root: None,
    )
    monkeypatch.setattr(
        hosted_gate,
        "workspace_detector_corpus_sha256",
        lambda root: _DETECTOR_SHA,
    )
    monkeypatch.setattr(hosted_gate, "sha256_file", lambda path: _BINARY_SHA)
    monkeypatch.setattr(hosted_gate, "capture_host", lambda: host)
    environ = {
        "GITHUB_ACTIONS": "true",
        "KEYHOG_BENCH_RUNNER_PROFILE": policy.profile,
        "RUNNER_NAME": "GitHub Actions 7",
        "RUNNER_OS": policy.runner_os,
        "RUNNER_ARCH": policy.runner_arch,
        "RUNNER_ENVIRONMENT": policy.runner_environment,
        "GITHUB_WORKFLOW": policy.workflow,
        "GITHUB_WORKFLOW_REF": _WORKFLOW_REF,
        "GITHUB_WORKFLOW_SHA": _COMMIT,
        "GITHUB_REPOSITORY": policy.repository,
        "GITHUB_RUN_ID": "1234",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_JOB": policy.job,
        "CUDA_VISIBLE_DEVICES": policy.cuda_visible_devices,
        "NVIDIA_VISIBLE_DEVICES": policy.nvidia_visible_devices,
    }

    with pytest.raises(
        hosted_gate.HostedCpuInputError,
        match="neither the exact finite allocation nor documented unbounded: observed='unknown'",
    ):
        hosted_gate.capture_context(
            policy_path,
            _COMMIT,
            binary,
            list(policy.workloads),
            repo_root=repo_root,
            snapshot_root=tmp_path / "snapshots",
            environ=environ,
            generated_at=_CONTEXT_TIME,
        )


def test_genuine_unbounded_quota_passes_with_exact_affinity(evidence):
    """A genuine cgroup v2 ``max`` marker remains usable when affinity proves exact four CPUs."""
    evidence["context"]["host"]["cgroup_quota_cores"] = "unbounded"
    _rebind_context(evidence)

    assert _violations(evidence) == []


def test_unbounded_quota_rejects_nonexact_affinity(evidence):
    """Unbounded quota alone cannot establish the runner class without exact process affinity."""
    evidence["context"]["host"]["cgroup_quota_cores"] = "unbounded"
    evidence["context"]["host"]["affinity_cores"] = 8

    assert any(
        "unbounded cgroup quota requires exact process affinity" in item
        for item in _violations(evidence)
    )


def test_incomplete_accelerator_inventory_does_not_claim_physical_no_gpu(evidence):
    """Missing NVIDIA tooling records an incomplete query while CPU/SIMD route evidence still passes."""
    assert "no_gpu" not in evidence["context"]
    receipt = evidence["context"]["accelerator_enforcement"]
    assert receipt["inventory"] == {
        "source": "nvidia-smi",
        "status": "nvidia-smi-unavailable",
        "devices": [],
    }
    assert _violations(evidence) == []


def test_observed_gpu_does_not_invalidate_enforced_cpu_route(evidence):
    """Physical accelerator presence is inventory, not proof that a CPU/SIMD policy row used it."""
    evidence["context"]["host"]["gpu"] = "NVIDIA Example"
    evidence["context"]["host"]["gpu_vram_mb"] = 8192
    evidence["context"]["accelerator_enforcement"]["inventory"] = {
        "source": "nvidia-smi",
        "status": "nvidia-smi-observed",
        "devices": [{"name": "NVIDIA Example", "vram_mb": 8192}],
    }
    _rebind_context(evidence)

    assert _violations(evidence) == []


def test_workload_digest_count_bytes_and_revision_are_independent_pins(evidence):
    """A matching corpus name once hid substituted bytes/revisions; every acquisition identity must agree."""
    evidence["context"]["acquisition"]["mirror"]["revision"] = "generator-v2"
    evidence["context"]["workloads"]["mirror"]["bytes"] += 1
    assert any("revision differs" in item for item in _violations(evidence))
    assert any("byte count differs" in item for item in _violations(evidence))


@pytest.mark.parametrize("mode", ["fast", "full", "deep", "precision"])
def test_every_recovery_mode_has_all_independent_phase_floors(evidence, mode):
    """Only deep once checked P00-P12; dropping one phase from any usable mode now fails that row."""
    row_id = f"recovery-{mode}"
    row = evidence["rows"][row_id]
    row["detection"]["per_category"].pop("recovery/p12-aes-structural-obfuscation")
    _rewrite(evidence["root"], evidence["policy"], row_id, row)
    assert any("scorer categories differ" in item for item in _violations(evidence))


def test_recovery_category_counts_must_conserve_overall_truth(evidence):
    """Individually plausible phase rows once double-counted truth; P00-P12 totals must conserve overall TP/FN."""
    row = evidence["rows"]["recovery-deep"]
    phase = row["detection"]["per_category"]["recovery/p00-plaintext"]
    phase.update(Outcome(tp=335, fn=1).to_json())
    _rewrite(evidence["root"], evidence["policy"], "recovery-deep", row)
    assert any("category totals do not conserve" in item for item in _violations(evidence))


def test_overall_counts_must_conserve_labeled_positive_denominator(evidence):
    """Impossible TP/FN totals once produced plausible recall; denominator conservation rejects them."""
    row = evidence["rows"]["mirror"]
    row["detection"]["overall"] = Outcome(tp=3001).to_json()
    _rewrite(evidence["root"], evidence["policy"], "mirror", row)
    assert any("denominator is impossible" in item for item in _violations(evidence))


def test_empty_policy_category_floor_uses_authenticated_scorer_denominators(evidence):
    """An empty floor list once rejected real mirror categories or skipped them; snapshot truth governs shape."""
    assert not next(row for row in evidence["policy"].rows if row.id == "mirror").categories
    assert evidence["rows"]["mirror"]["detection"]["per_category"] == {
        "api": Outcome(tp=3000).to_json()
    }
    assert _violations(evidence) == []


def test_unexpected_truth_category_rejects_even_without_policy_floors(evidence):
    """A substituted positive category can hide missed authenticated truth, so only zero-truth extras are valid."""
    row = evidence["rows"]["mirror"]
    row["detection"]["per_category"]["forged"] = Outcome(tp=1).to_json()
    _rewrite(evidence["root"], evidence["policy"], "mirror", row)
    assert any("scorer categories differ" in item for item in _violations(evidence))


def test_false_positive_only_category_remains_in_authenticated_scoring(evidence):
    """A detector can emit an FP in a category absent from positive truth; rejecting it would hide honest errors."""
    row = evidence["rows"]["mirror"]
    row["detection"]["per_category"]["negative-only-detector"] = Outcome(fp=7).to_json()
    overall = row["detection"]["overall"]
    row["detection"]["overall"] = Outcome(
        tp=overall["tp"], fp=overall["fp"] + 7, fn=overall["fn"]
    ).to_json()
    _rewrite(evidence["root"], evidence["policy"], "mirror", row)
    assert _violations(evidence) == []


def test_false_positive_category_must_conserve_overall_count(evidence):
    """An extra negative-only category cannot carry uncounted errors outside the overall precision denominator."""
    row = evidence["rows"]["mirror"]
    row["detection"]["per_category"]["negative-only-detector"] = Outcome(fp=7).to_json()
    _rewrite(evidence["root"], evidence["policy"], "mirror", row)
    assert any("category totals do not conserve overall counts" in item for item in _violations(evidence))


@pytest.mark.parametrize(
    "field",
    [
        "context_sha256", "repository", "workflow_ref", "workflow_sha", "run_id",
        "run_attempt", "job", "release_executable_sha256", "test_executable_sha256",
        "parity_source_sha256", "vector_sha256", "detector_examples",
        "unicode_divergences",
    ],
)
def test_parity_receipt_binds_every_source_run_and_vector_axis(evidence, field):
    """An explicit zero once floated across binaries/runs/vectors; each parity identity is independently bound."""
    evidence["parity"][field] = 1 if field in {"detector_examples", "unicode_divergences"} else "8" * 64
    assert any(f"Unicode parity {field}" in item for item in _violations(evidence))


def test_result_context_digest_binding_rejects_post_context_rewrite(evidence):
    """Mutating context after scans once retained valid-looking rows; result bindings require exact context bytes."""
    evidence["context"]["runner"]["name"] = "rewritten runner"
    rewritten_sha = hashlib.sha256(_json_bytes(evidence["context"])).hexdigest()
    assert rewritten_sha != evidence["context_sha"]
    assert any("context_sha256" in item or "binding differs" in item for item in _violations(evidence))


def test_stale_row_predating_context_fails(evidence):
    """Old result JSON once joined a fresh receipt; rows before context creation are inadmissible."""
    evidence["rows"]["mirror"]["generated_at"] = "2026-07-27T09:59:59+00:00"
    _rewrite(evidence["root"], evidence["policy"], "mirror", evidence["rows"]["mirror"])
    assert any("outside current-run UTC" in item for item in _violations(evidence))


def test_missing_required_row_fails_without_rerun(evidence):
    """A missing deep row once triggered fallback/partial success; result-only validation reports it unusable."""
    requirement = next(row for row in evidence["policy"].rows if row.id == "recovery-deep")
    (evidence["root"] / requirement.path).unlink()
    assert any("recovery-deep" in item and "cannot load" in item for item in _violations(evidence))


def test_gate_cli_status_is_zero_only_for_complete_current_evidence(evidence, tmp_path):
    """CLI integration once omitted trusted inputs; a complete bound bundle alone returns release-success zero."""
    context_path = tmp_path / "context.json"
    parity_path = tmp_path / "parity.json"
    context_path.write_bytes(_json_bytes(evidence["context"]))
    parity_path.write_bytes(_json_bytes(evidence["parity"]))
    assert run_gate(
        evidence["policy_path"], context_path, parity_path, evidence["root"],
        trusted=evidence["trusted"],
    ) == 0
    evidence["parity"]["unicode_divergences"] = 1
    parity_path.write_bytes(_json_bytes(evidence["parity"]))
    assert run_gate(
        evidence["policy_path"], context_path, parity_path, evidence["root"],
        trusted=evidence["trusted"],
    ) == 1
