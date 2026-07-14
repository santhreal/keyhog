"""Immutable provenance for the official AgentRE-Bench Linux recovery slice."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from urllib.parse import quote

UPSTREAM_REPOSITORY_URL = "https://github.com/agentrebench/AgentRE-Bench"
UPSTREAM_REPOSITORY_COMMIT = "9b995bf9301d0204319434d637a5504fb5abccf3"
UPSTREAM_LICENSE = "MIT"
UPSTREAM_LICENSE_COPYRIGHT = "Copyright (c) 2026 agentrebench"
RAW_ROOT = (
    "https://raw.githubusercontent.com/agentrebench/AgentRE-Bench/"
    f"{UPSTREAM_REPOSITORY_COMMIT}"
)
TASK_SELECTION_SCHEMA = "agentre-linux-task-selection-v1"
TASK_SELECTOR = "exclude-task-id-prefix:windows_"
UPSTREAM_TASK_COUNT = 23


@dataclass(frozen=True)
class PinnedArtifact:
    """A repository-relative upstream file with its content digest."""

    path: str
    sha256: str

    def __post_init__(self) -> None:
        if self.path.startswith("/") or ".." in self.path.split("/"):
            raise ValueError(
                f"artifact path must stay repository-relative: {self.path!r}"
            )
        if len(self.sha256) != 64 or any(
            c not in "0123456789abcdef" for c in self.sha256
        ):
            raise ValueError(f"artifact SHA-256 is not canonical: {self.sha256!r}")

    @property
    def raw_url(self) -> str:
        return f"{RAW_ROOT}/{quote(self.path, safe='/')}"

    def verify(self, payload: bytes) -> None:
        observed = hashlib.sha256(payload).hexdigest()
        if observed != self.sha256:
            raise ValueError(
                f"upstream artifact digest mismatch for {self.path}: "
                f"expected {self.sha256}, observed {observed}"
            )


@dataclass(frozen=True)
class AgentRETask:
    """Official task identity and repository paths from pinned tasks.json."""

    task_id: str
    source_path: str
    binary_name: str
    ground_truth_path: str
    difficulty: int


@dataclass(frozen=True)
class AgentRETaskSelection:
    """Exact Linux task slice derived from the pinned upstream manifest."""

    tasks: tuple[AgentRETask, ...]
    manifest_sha256: str
    selection_sha256: str

    def receipt(self) -> dict[str, object]:
        """Return the stable task identity embedded in benchmark receipts."""

        return {
            "schema": TASK_SELECTION_SCHEMA,
            "selector": TASK_SELECTOR,
            "manifest_sha256": self.manifest_sha256,
            "selection_sha256": self.selection_sha256,
            "task_count": len(self.tasks),
        }


CONTROL_ARTIFACTS = (
    PinnedArtifact(
        "LICENSE", "fd6435e67fc4e7cca611b5a4c3eb5d53d97f8423bd171872f3cbc2e6e7d1f072"
    ),
    PinnedArtifact(
        "tasks.json", "514523220d1915f4153a927cf66db9ef92901d4352964dc205271d872b338e8a"
    ),
    PinnedArtifact(
        "build_binaries.sh",
        "18d7136e07025d3b3969d5a605167be666f93c04a3bf474cec11650751711cb5",
    ),
    PinnedArtifact(
        "scorer.py", "ad5b6b5d212cce1e44b30b8c31048e3d7064caa02c8d3202819b76388fde3365"
    ),
)

SOURCE_ARTIFACTS = (
    PinnedArtifact(
        "samples/level1_TCPServer.c",
        "dcf80f4f5b1c75a6f353c4414942935caa6d0d83bd74af8353c05deec3dbfcb7",
    ),
    PinnedArtifact(
        "samples/level2_XorEncodedStrings.c",
        "b2c19581e666fbe9836b4a01730c9cf1babda7fc3ac0cd471e1867ea41c04a3f",
    ),
    PinnedArtifact(
        "samples/level3_anti-debugging_reverseShell.c",
        "d8685ceac822d256a6613a591e85c4f8c3c3b65a4246bf1f74e780b61873ac15",
    ),
    PinnedArtifact(
        "samples/level4_polymorphicReverseShell.c",
        "fd4733bb056a0af5511e0f29c32a985caf0fc5a71342f25a2fe34cf2260840b8",
    ),
    PinnedArtifact(
        "samples/level5_MultistageReverseShell.c",
        "e429a9761825644c769d952138a066d6f4b299aa8d4476668650768bfe8f1031",
    ),
    PinnedArtifact(
        "samples/level6_ICMP Covert Channel Shell.c",
        "239c06c606f530c2de1b232316e81701dc68876bfb0b965d195f432e2fd19fc9",
    ),
    PinnedArtifact(
        "samples/level7_DNS_TunnelReverse Shell.c",
        "b8e2b3fa6ec0c3ea9807e990b7f1116691ca7c6090eeb4b01b98279204f4d3d0",
    ),
    PinnedArtifact(
        "samples/level8_Process_hollowing_reverse_shell.c",
        "b48984a1b524aa772da3cd4ec8a3b337ffe530cb7cb371178a9aa00cd1a7d599",
    ),
    PinnedArtifact(
        "samples/level9_SharedObjectInjectionReverseShell.c",
        "0c2ea0a6970cb803bb40101b624afceafd703934ccfcc64c2b8e0cb51d83b765",
    ),
    PinnedArtifact(
        "samples/level10_fully_obfuscated_AES_Encrypted Shell.c",
        "71e23b84b8b75b3b4a1afaf91c267758f9b1c9e70a3de8e899ce7b0157732c03",
    ),
    PinnedArtifact(
        "samples/level11_ForkBombReverseShell.c",
        "456d03bf58f347e1f5d40e9528b65e4ca396a7519489991725a1a71f0abb9332",
    ),
    PinnedArtifact(
        "samples/level12_JIT_Compiled_Shellcode.c",
        "eea47c0e196038970c35e1ff713ec9a5d77d228b68b92944f377e03c3d8670cb",
    ),
    PinnedArtifact(
        "samples/level13_MetamorphicDropper.c",
        "c0949e37d76bd1bdc101faccb48f8114bd18a582d78a972988d0fa5f8f1c552a",
    ),
)

GROUND_TRUTH_ARTIFACTS = (
    PinnedArtifact(
        "ground_truths/level1_TCPServer.json",
        "5c568fde90a069b0133adb93e98e83e56a0ca98342cab5a41e11aa4a988a9120",
    ),
    PinnedArtifact(
        "ground_truths/level2_XorEncodedStrings.json",
        "1d5e5e21296b26bf419fc82c9be8d329c508efd3900a5b05e2e6fd0e774a5b01",
    ),
    PinnedArtifact(
        "ground_truths/level3_anti-debugging_reverseShell.json",
        "0ef8618583777b9bda6284f67a51f9447f63c7426b6f212546870d0009147d83",
    ),
    PinnedArtifact(
        "ground_truths/level4_polymorphicReverseShell.json",
        "627a16652f97a83d5ef5e2e8e20f6fc7b6a2a2b71d812a3315c05e49f8dfda2e",
    ),
    PinnedArtifact(
        "ground_truths/level5_MultistageReverseShell.json",
        "fdc60cdd27cd7021546f0456358f627b11a98c9fdd45e153d6c8a358cbc664e2",
    ),
    PinnedArtifact(
        "ground_truths/level6_ICMP_CovertChannelShell.json",
        "a57a2b5ddbc763b592affedfda05b7f7611dd336cb989f06e17e79880a58d440",
    ),
    PinnedArtifact(
        "ground_truths/level7_DNS_TunnelReverseShell.json",
        "5495c9340a8144a6df326ce48bdc8a14b4701248abfefcca247c87080fbc7a05",
    ),
    PinnedArtifact(
        "ground_truths/level8_Process_hollowing_reverse_shell.json",
        "c4bb598e1ff59bd80ff398233736c732b14c028ce04d998b74f036a80c88658b",
    ),
    PinnedArtifact(
        "ground_truths/level9_SharedObjectInjectionReverseShell.json",
        "1792a2453b19f364a2c6f1952c2f08b39018e23322972147a23efe9d6a1631a7",
    ),
    PinnedArtifact(
        "ground_truths/level10_fully_obfuscated_AES_Encrypted_Shell.json",
        "8a86044abdf2ab2c43428b53841d44a0f8b8803d9a70402c7ec438d0db5467a2",
    ),
    PinnedArtifact(
        "ground_truths/level11_ForkBombReverseShell.json",
        "f4d28853aaddff23210b08f96a65e988e3ba6086bf189904e05e8b3ef95493a6",
    ),
    PinnedArtifact(
        "ground_truths/level12_JIT_Compiled_Shellcode.json",
        "0ae90601fe76e32d837425df66e7e71c21628c1049013ce1630b244d4c78c45e",
    ),
    PinnedArtifact(
        "ground_truths/level13_MetamorphicDropper.json",
        "d1bc65cd8d8b42152938220cbbe0c6eccf700ffd3f99fec7ff8e6645e94b1e03",
    ),
)

LINUX_TASKS = (
    AgentRETask(
        "level1_TCPServer",
        "samples/level1_TCPServer.c",
        "level1_TCPServer",
        "ground_truths/level1_TCPServer.json",
        1,
    ),
    AgentRETask(
        "level2_XorEncodedStrings",
        "samples/level2_XorEncodedStrings.c",
        "level2_XorEncodedStrings",
        "ground_truths/level2_XorEncodedStrings.json",
        2,
    ),
    AgentRETask(
        "level3_anti-debugging_reverseShell",
        "samples/level3_anti-debugging_reverseShell.c",
        "level3_anti-debugging_reverseShell",
        "ground_truths/level3_anti-debugging_reverseShell.json",
        3,
    ),
    AgentRETask(
        "level4_polymorphicReverseShell",
        "samples/level4_polymorphicReverseShell.c",
        "level4_polymorphicReverseShell",
        "ground_truths/level4_polymorphicReverseShell.json",
        4,
    ),
    AgentRETask(
        "level5_MultistageReverseShell",
        "samples/level5_MultistageReverseShell.c",
        "level5_MultistageReverseShell",
        "ground_truths/level5_MultistageReverseShell.json",
        5,
    ),
    AgentRETask(
        "level6_ICMP_CovertChannelShell",
        "samples/level6_ICMP Covert Channel Shell.c",
        "level6_ICMP_Covert_Channel_Shell",
        "ground_truths/level6_ICMP_CovertChannelShell.json",
        6,
    ),
    AgentRETask(
        "level7_DNS_TunnelReverseShell",
        "samples/level7_DNS_TunnelReverse Shell.c",
        "level7_DNS_TunnelReverse_Shell",
        "ground_truths/level7_DNS_TunnelReverseShell.json",
        7,
    ),
    AgentRETask(
        "level8_Process_hollowing_reverse_shell",
        "samples/level8_Process_hollowing_reverse_shell.c",
        "level8_Process_hollowing_reverse_shell",
        "ground_truths/level8_Process_hollowing_reverse_shell.json",
        8,
    ),
    AgentRETask(
        "level9_SharedObjectInjectionReverseShell",
        "samples/level9_SharedObjectInjectionReverseShell.c",
        "level9_SharedObjectInjectionReverseShell",
        "ground_truths/level9_SharedObjectInjectionReverseShell.json",
        9,
    ),
    AgentRETask(
        "level10_fully_obfuscated_AES_Encrypted_Shell",
        "samples/level10_fully_obfuscated_AES_Encrypted Shell.c",
        "level10_fully_obfuscated_AES_Encrypted_Shell",
        "ground_truths/level10_fully_obfuscated_AES_Encrypted_Shell.json",
        10,
    ),
    AgentRETask(
        "level11_ForkBombReverseShell",
        "samples/level11_ForkBombReverseShell.c",
        "level11_ForkBombReverseShell",
        "ground_truths/level11_ForkBombReverseShell.json",
        11,
    ),
    AgentRETask(
        "level12_JIT_Compiled_Shellcode",
        "samples/level12_JIT_Compiled_Shellcode.c",
        "level12_JIT_Compiled_Shellcode",
        "ground_truths/level12_JIT_Compiled_Shellcode.json",
        12,
    ),
    AgentRETask(
        "level13_MetamorphicDropper",
        "samples/level13_MetamorphicDropper.c",
        "level13_MetamorphicDropper",
        "ground_truths/level13_MetamorphicDropper.json",
        13,
    ),
)


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError(f"AgentRE tasks manifest repeats JSON key {key!r}")
        output[key] = value
    return output


def _manifest_task(row: object, index: int) -> AgentRETask:
    if not isinstance(row, dict):
        raise ValueError(f"AgentRE task row {index} must be a JSON object")
    expected_fields = {
        "task_id",
        "source_file",
        "binary_name",
        "ground_truth",
        "difficulty",
    }
    if set(row) != expected_fields:
        raise ValueError(
            f"AgentRE task row {index} fields are invalid: "
            f"missing={sorted(expected_fields - set(row))}, "
            f"unexpected={sorted(set(row) - expected_fields)}"
        )
    strings = {
        field: row[field]
        for field in ("task_id", "source_file", "binary_name", "ground_truth")
    }
    for field, value in strings.items():
        if not isinstance(value, str) or not value:
            raise ValueError(
                f"AgentRE task row {index} field {field!r} must be a nonempty string"
            )
    difficulty = row["difficulty"]
    if type(difficulty) is not int or difficulty <= 0:
        raise ValueError(
            f"AgentRE task row {index} difficulty must be a positive integer"
        )
    for field in ("source_file", "ground_truth"):
        path = strings[field]
        if path.startswith("/") or ".." in path.split("/"):
            raise ValueError(
                f"AgentRE task row {index} field {field!r} must stay repository-relative"
            )
    return AgentRETask(
        task_id=strings["task_id"],
        source_path=strings["source_file"],
        binary_name=strings["binary_name"],
        ground_truth_path=strings["ground_truth"],
        difficulty=difficulty,
    )


def _selection_digest(tasks: tuple[AgentRETask, ...]) -> str:
    rows = [
        {
            "task_id": task.task_id,
            "source_file": task.source_path,
            "binary_name": task.binary_name,
            "ground_truth": task.ground_truth_path,
            "difficulty": task.difficulty,
        }
        for task in tasks
    ]
    identity = {
        "schema": TASK_SELECTION_SCHEMA,
        "selector": TASK_SELECTOR,
        "tasks": rows,
    }
    encoded = json.dumps(
        identity, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def expected_linux_task_selection() -> AgentRETaskSelection:
    """Return the task identity expected from the pinned upstream manifest."""

    tasks_manifest = next(
        artifact for artifact in CONTROL_ARTIFACTS if artifact.path == "tasks.json"
    )
    return AgentRETaskSelection(
        tasks=LINUX_TASKS,
        manifest_sha256=tasks_manifest.sha256,
        selection_sha256=_selection_digest(LINUX_TASKS),
    )


def parse_linux_task_selection(raw: str) -> AgentRETaskSelection:
    """Strictly derive and verify the Linux slice from pinned tasks.json text."""

    try:
        document = json.loads(raw, object_pairs_hook=_unique_json_object)
    except json.JSONDecodeError as exc:
        raise ValueError(f"AgentRE tasks manifest is invalid JSON: {exc}") from exc
    if not isinstance(document, dict) or set(document) != {"tasks"}:
        raise ValueError("AgentRE tasks manifest must contain only the tasks array")
    rows = document["tasks"]
    if not isinstance(rows, list) or len(rows) != UPSTREAM_TASK_COUNT:
        observed = len(rows) if isinstance(rows, list) else "non-array"
        raise ValueError(
            f"AgentRE tasks manifest must contain {UPSTREAM_TASK_COUNT} rows; "
            f"observed {observed}"
        )
    tasks = tuple(_manifest_task(row, index) for index, row in enumerate(rows))
    for field, values in (
        ("task_id", [task.task_id for task in tasks]),
        ("source_file", [task.source_path for task in tasks]),
        ("binary_name", [task.binary_name for task in tasks]),
        ("ground_truth", [task.ground_truth_path for task in tasks]),
        ("difficulty", [task.difficulty for task in tasks]),
    ):
        if len(values) != len(set(values)):
            raise ValueError(f"AgentRE tasks manifest repeats {field}")
    selected = tuple(task for task in tasks if not task.task_id.startswith("windows_"))
    expected = expected_linux_task_selection()
    if selected != expected.tasks:
        raise ValueError(
            "AgentRE Linux task selection differs from the reviewed benchmark slice"
        )
    if _selection_digest(selected) != expected.selection_sha256:
        raise ValueError("AgentRE Linux task selection digest is inconsistent")
    return expected


OFFICIAL_LINUX_SLICE = CONTROL_ARTIFACTS + SOURCE_ARTIFACTS + GROUND_TRUTH_ARTIFACTS
