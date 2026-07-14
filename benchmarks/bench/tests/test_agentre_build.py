import hashlib
import pathlib
import stat
import struct

import pytest

from bench.agentre_build import (
    GCC_IMAGE,
    AgentREBinaryBuilder,
    AgentREBuildError,
)
from bench.agentre_provenance import LINUX_TASKS


class FakeMaterializer:
    def read_pinned_texts(self, paths):
        return [
            (pathlib.Path(path), "int main(void) { return 0; }\n") for path in paths
        ]


def fake_elf(name: str, *, shared: bool) -> bytes:
    payload = bytearray(64)
    payload[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", payload, 16, 3 if shared else 2, 62)
    payload.extend(name.encode())
    return bytes(payload)


def fake_inventory():
    return {
        task.binary_name: hashlib.sha256(
            fake_elf(task.binary_name, shared=task.difficulty == 9)
        ).hexdigest()
        for task in LINUX_TASKS
    }


def test_build_uses_pinned_offline_nonexecuting_compiler_and_seals_exact_outputs(
    tmp_path,
):
    calls = []

    def runner(argv, output, timeout):
        calls.append((argv, output, timeout))
        output.write_bytes(
            fake_elf(output.name, shared=output.name.startswith("level9_"))
        )

    output = tmp_path / "agentre-binaries"
    builder = AgentREBinaryBuilder(
        output,
        materializer=FakeMaterializer(),
        _runner=runner,
        _expected=fake_inventory(),
    )

    assert builder.build() == output
    receipt = builder.validate()

    assert len(calls) == 13
    assert len(receipt["binaries"]) == 13
    assert receipt["image"] == GCC_IMAGE
    for task, (argv, binary, timeout) in zip(LINUX_TASKS, calls):
        assert argv[:2] == ["docker", "run"]
        assert "--network" in argv and argv[argv.index("--network") + 1] == "none"
        assert "--read-only" in argv
        assert ["--cap-drop", "ALL"] == argv[
            argv.index("--cap-drop") : argv.index("--cap-drop") + 2
        ]
        assert "no-new-privileges" in argv
        assert argv[argv.index("--platform") + 1] == "linux/amd64"
        assert GCC_IMAGE in argv
        assert argv[argv.index(GCC_IMAGE) + 1] == "gcc"
        assert f"/src/{pathlib.Path(task.source_path).name}" in argv
        assert binary.name == task.binary_name
        assert binary.parent.name == "outputs"
        assert timeout == 120
        assert stat.S_IMODE((output / task.binary_name).stat().st_mode) == 0o400
    assert stat.S_IMODE(output.stat().st_mode) == 0o500
    assert stat.S_IMODE((output / "build-receipt.json").stat().st_mode) == 0o400
    assert not list(tmp_path.glob(".agentre-binaries-*.staging"))


def test_level_nine_is_shared_and_other_levels_are_static_executables(tmp_path):
    commands = {}

    def runner(argv, output, _timeout):
        commands[output.name] = argv
        output.write_bytes(
            fake_elf(output.name, shared=output.name.startswith("level9_"))
        )

    AgentREBinaryBuilder(
        tmp_path / "out",
        materializer=FakeMaterializer(),
        _runner=runner,
        _expected=fake_inventory(),
    ).build()

    for name, argv in commands.items():
        compile_argv = argv[argv.index(GCC_IMAGE) + 1 :]
        if name.startswith("level9_"):
            assert "-shared" in compile_argv
            assert "-fPIC" in compile_argv
            assert "-static" not in compile_argv
        else:
            assert "-static" in compile_argv
            assert "-shared" not in compile_argv


def test_digest_mismatch_fails_closed_and_removes_staging(tmp_path):
    def runner(_argv, output, _timeout):
        output.write_bytes(
            fake_elf(output.name, shared=output.name.startswith("level9_"))
        )

    expected = fake_inventory()
    expected[LINUX_TASKS[0].binary_name] = "0" * 64
    output = tmp_path / "agentre-binaries"

    with pytest.raises(AgentREBuildError, match="binary digest mismatch"):
        AgentREBinaryBuilder(
            output,
            materializer=FakeMaterializer(),
            _runner=runner,
            _expected=expected,
        ).build()

    assert not output.exists()
    assert not list(tmp_path.glob(".agentre-binaries-*.staging"))


def test_compiler_failure_fails_closed_and_removes_partial_outputs(tmp_path):
    calls = 0

    def runner(_argv, output, _timeout):
        nonlocal calls
        calls += 1
        if calls == 3:
            raise AgentREBuildError("injected compiler failure")
        output.write_bytes(
            fake_elf(output.name, shared=output.name.startswith("level9_"))
        )

    output = tmp_path / "agentre-binaries"
    with pytest.raises(AgentREBuildError, match="injected compiler failure"):
        AgentREBinaryBuilder(
            output,
            materializer=FakeMaterializer(),
            _runner=runner,
            _expected=fake_inventory(),
        ).build()

    assert not output.exists()
    assert not list(tmp_path.glob(".agentre-binaries-*.staging"))


def test_validation_rejects_replaced_binary_even_when_resealed(tmp_path):
    def runner(_argv, output, _timeout):
        output.write_bytes(
            fake_elf(output.name, shared=output.name.startswith("level9_"))
        )

    output = tmp_path / "agentre-binaries"
    builder = AgentREBinaryBuilder(
        output,
        materializer=FakeMaterializer(),
        _runner=runner,
        _expected=fake_inventory(),
    )
    builder.build()
    target = output / LINUX_TASKS[0].binary_name
    output.chmod(0o700)
    target.chmod(0o600)
    target.write_bytes(fake_elf(target.name + "-replacement", shared=False))
    target.chmod(0o400)
    output.chmod(0o500)

    with pytest.raises(AgentREBuildError, match="binary digest mismatch"):
        builder.validate()


def test_validation_rejects_unexpected_output(tmp_path):
    def runner(_argv, output, _timeout):
        output.write_bytes(
            fake_elf(output.name, shared=output.name.startswith("level9_"))
        )

    output = tmp_path / "agentre-binaries"
    builder = AgentREBinaryBuilder(
        output,
        materializer=FakeMaterializer(),
        _runner=runner,
        _expected=fake_inventory(),
    )
    builder.build()
    output.chmod(0o700)
    unexpected = output / "unexpected"
    unexpected.write_bytes(b"x")
    unexpected.chmod(0o400)
    output.chmod(0o500)

    with pytest.raises(AgentREBuildError, match="inventory mismatch"):
        builder.validate()
