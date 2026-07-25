"""Behavioral regressions for ordered, resumable crates.io publication."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import socket
import tarfile
import tempfile
import textwrap
import threading
import unittest
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

VERSION = "0.5.45"
CRATES = [
    "keyhog-core",
    "keyhog-verifier",
    "keyhog-sources",
    "keyhog-scanner",
    "keyhog",
]
DEPENDENCIES = {
    "keyhog-core": [],
    "keyhog-verifier": ["keyhog-core"],
    "keyhog-sources": ["keyhog-core", "keyhog-verifier"],
    "keyhog-scanner": ["keyhog-core", "keyhog-verifier"],
    "keyhog": ["keyhog-core", "keyhog-verifier", "keyhog-sources", "keyhog-scanner"],
}
SECRET = "registry-token-must-stay-secret"


def crate_archive(crate: str) -> bytes:
    """Return a valid deterministic crate archive for the fake registry."""

    manifest = f'[package]\nname = "{crate}"\nversion = "{VERSION}"\n'.encode()
    compressed = io.BytesIO()
    with gzip.GzipFile(
        filename="", fileobj=compressed, mode="wb", mtime=0
    ) as zipped:
        with tarfile.open(fileobj=zipped, mode="w") as archive:
            entry = tarfile.TarInfo(f"{crate}-{VERSION}/Cargo.toml")
            entry.size = len(manifest)
            entry.mtime = 0
            entry.mode = 0o644
            archive.addfile(entry, io.BytesIO(manifest))
    return compressed.getvalue()


@dataclass
class RegistryState:
    """Fake registry bytes and mutation history."""

    archives: dict[str, bytes] = field(default_factory=dict)
    publish_order: list[str] = field(default_factory=list)
    corrupt_upload_for: str | None = None
    visibility_404s: dict[str, int] = field(default_factory=dict)
    permanent_404_for: str | None = None
    transport_error_for: str | None = None
    poll_requests: dict[str, int] = field(default_factory=dict)
    poll_authorizations: list[str | None] = field(default_factory=list)


class RegistryHandler(BaseHTTPRequestHandler):
    """Serve the crates.io endpoints exercised by ``publish.sh``."""

    server: "RegistryServer"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def reply(self, status: int, body: bytes = b"", content_type: str = "") -> None:
        self.send_response(status)
        if body:
            self.send_header("Content-Length", str(len(body)))
            if content_type:
                self.send_header("Content-Type", content_type)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self) -> None:
        parts = urlsplit(self.path).path.strip("/").split("/")
        if len(parts) not in {5, 6} or parts[:3] != ["api", "v1", "crates"]:
            self.reply(404)
            return
        crate = unquote(parts[3])
        version = unquote(parts[4])
        content = self.server.state.archives.get(crate)
        if version != VERSION or content is None:
            self.reply(404, b'{"errors":[{"detail":"not found"}]}', "application/json")
            return
        if len(parts) == 5 and crate in self.server.state.publish_order:
            self.server.state.poll_requests[crate] = (
                self.server.state.poll_requests.get(crate, 0) + 1
            )
            self.server.state.poll_authorizations.append(
                self.headers.get("Authorization")
            )
            if self.server.state.transport_error_for == crate:
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            if self.server.state.permanent_404_for == crate:
                self.reply(404, b'{"errors":[{"detail":"not found"}]}', "application/json")
                return
            remaining_404s = self.server.state.visibility_404s.get(crate, 0)
            if remaining_404s:
                self.server.state.visibility_404s[crate] = remaining_404s - 1
                self.reply(404, b'{"errors":[{"detail":"not found"}]}', "application/json")
                return
        if len(parts) == 6:
            if parts[5] != "download":
                self.reply(404)
                return
            self.reply(200, content, "application/gzip")
            return
        document = {
            "version": {"checksum": hashlib.sha256(content).hexdigest()}
        }
        self.reply(200, json.dumps(document).encode(), "application/json")

    def do_POST(self) -> None:
        parts = urlsplit(self.path).path.strip("/").split("/")
        if len(parts) != 3 or parts[:2] != ["test", "publish"]:
            self.reply(404)
            return
        crate = unquote(parts[2])
        missing = [
            dependency
            for dependency in DEPENDENCIES.get(crate, ["unknown-crate"])
            if dependency not in self.server.state.archives
        ]
        if missing:
            self.reply(
                409,
                json.dumps({"missing_dependencies": missing}).encode(),
                "application/json",
            )
            return
        length = int(self.headers.get("Content-Length", "0"))
        content = self.rfile.read(length)
        self.server.state.publish_order.append(crate)
        if self.server.state.corrupt_upload_for == crate:
            content += b"corrupted-by-registry"
        self.server.state.archives[crate] = content
        self.reply(201, b"{}", "application/json")


class RegistryServer(ThreadingHTTPServer):
    """HTTP registry carrying mutable test state."""

    def __init__(self, state: RegistryState) -> None:
        super().__init__(("127.0.0.1", 0), RegistryHandler)
        self.state = state


class PublishScriptTests(unittest.TestCase):
    """Exercise publication against local Cargo, Git, and registry doubles."""

    def setUp(self) -> None:
        self.state = RegistryState()
        self.server = RegistryServer(self.state)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.automation = self.root / "automation"
        self.source = self.root / "tagged-source"
        self.bin = self.root / "fake-bin"
        self.bin.mkdir()
        (self.automation / "scripts" / "gates").mkdir(parents=True)
        (self.source / "scripts").mkdir(parents=True)
        (self.root / "tmp").mkdir()
        publisher = Path(__file__).parents[1] / "publish.sh"
        shutil.copy2(publisher, self.automation / "scripts" / "publish.sh")
        (self.source / "Cargo.toml").write_text(
            f'[workspace.package]\nversion = "{VERSION}"\n', encoding="utf-8"
        )
        (self.automation / "Cargo.toml").write_text(
            '[workspace.package]\nversion = "99.0.0"\n', encoding="utf-8"
        )
        self.poison_marker = self.root / "tag-stale-publisher-ran"
        self._write_executable(
            self.source / "scripts" / "publish.sh",
            "#!/usr/bin/env python3\n"
            "import os\n"
            "from pathlib import Path\n"
            "Path(os.environ['POISON_MARKER']).write_text('tag publisher ran')\n"
            "raise SystemExit(91)\n",
        )
        self.gate_log = self.root / "gate.log"
        self._write_executable(
            self.automation / "scripts" / "gates" / "package_licenses.py",
            self._gate_program(),
        )
        self._write_executable(self.bin / "cargo", self._cargo_program())
        self._write_executable(
            self.bin / "git",
            "#!/usr/bin/env python3\n"
            "import os\n"
            "from pathlib import Path\n"
            "if (Path(os.environ['TEST_SOURCE_ROOT']) / 'dirty-marker').exists():\n"
            "    print('?? dirty-marker')\n"
            "raise SystemExit(0)\n",
        )
        self.sleep_marker = self.root / "unexpected-fixed-sleep"
        self._write_executable(
            self.bin / "sleep",
            "#!/usr/bin/env python3\n"
            "import os\n"
            "from pathlib import Path\n"
            "Path(os.environ['SLEEP_MARKER']).write_text('fixed sleep invoked')\n"
            "raise SystemExit(97)\n",
        )

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.tempdir.cleanup()

    @staticmethod
    def _write_executable(path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)

    def _gate_program(self) -> str:
        return textwrap.dedent(
            f"""\
            #!/usr/bin/env python3
            import json
            import os
            import pathlib
            import sys

            REPO = pathlib.Path(".")

            def main(args):
                if "CARGO_REGISTRY_TOKEN" in os.environ:
                    raise SystemExit("gate inherited the crates.io credential")
                if REPO.resolve() != pathlib.Path({str(self.source)!r}).resolve():
                    raise SystemExit(f"gate received untagged source root: {{REPO}}")
                expected_tiers = [
                    "--publish-tier", "keyhog-core",
                    "--publish-tier", "keyhog-verifier",
                    "--publish-tier", "keyhog-sources", "keyhog-scanner",
                    "--publish-tier", "keyhog",
                ]
                if "--publish-tier" in args and args != expected_tiers:
                    raise SystemExit(f"wrong publication tiers: {{args!r}}")
                if "--require-all-archives" in args:
                    names = [pathlib.Path(value).name for value in args[1:]]
                    expected = [f"{{crate}}-{VERSION}.crate" for crate in {CRATES!r}]
                    if names != expected:
                        raise SystemExit(f"wrong final archive inventory: {{names!r}}")
                with pathlib.Path({str(self.gate_log)!r}).open("a", encoding="utf-8") as log:
                    log.write(json.dumps(args) + "\\n")
                return 0

            if __name__ == "__main__":
                raise SystemExit(main(sys.argv[1:]))
            """
        )

    def _cargo_program(self) -> str:
        return textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import gzip
            import io
            import os
            import pathlib
            import sys
            import tarfile
            import urllib.parse
            import urllib.request

            args = sys.argv[1:]
            version = os.environ["TEST_CRATE_VERSION"]
            source_root = pathlib.Path(os.environ["TEST_SOURCE_ROOT"]).resolve()
            registry_token = os.environ.get("CARGO_REGISTRY_TOKEN")
            if args[0] in ("build", "package") and registry_token is not None:
                raise SystemExit(f"{args[0]} inherited the crates.io credential")
            if pathlib.Path.cwd().resolve() != source_root:
                raise SystemExit(f"cargo ran outside immutable tagged source: {pathlib.Path.cwd()}")
            target = pathlib.Path(os.environ.get("CARGO_TARGET_DIR", "."))
            if args[0] == "build":
                raise SystemExit(0)
            if args[0] == "package":
                crate = args[args.index("--package") + 1]
                manifest = f'[package]\\nname = "{crate}"\\nversion = "{version}"\\n'.encode()
                output = target / "package" / f"{crate}-{version}.crate"
                output.parent.mkdir(parents=True, exist_ok=True)
                with output.open("wb") as raw:
                    with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as zipped:
                        with tarfile.open(fileobj=zipped, mode="w") as archive:
                            entry = tarfile.TarInfo(f"{crate}-{version}/Cargo.toml")
                            entry.size = len(manifest)
                            entry.mtime = 0
                            entry.mode = 0o644
                            archive.addfile(entry, io.BytesIO(manifest))
                raise SystemExit(0)
            if args[0] == "publish":
                if registry_token != os.environ["TEST_EXPECTED_REGISTRY_TOKEN"]:
                    raise SystemExit("cargo publish did not receive the exact registry token")
                if "--no-verify" not in args:
                    raise SystemExit("credential-bearing cargo publish may execute tagged build scripts")
                crate = args[args.index("-p") + 1]
                archive = target / "package" / f"{crate}-{version}.crate"
                request = urllib.request.Request(
                    os.environ["CRATES_IO_API_BASE"]
                    + "/test/publish/"
                    + urllib.parse.quote(crate, safe=""),
                    data=archive.read_bytes(),
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=5):
                    pass
                print(f"uploaded {crate} {version}")
                raise SystemExit(0)
            raise SystemExit(f"unexpected fake cargo invocation: {args!r}")
            """
        )

    def run_publish(
        self,
        *,
        include_token: bool = True,
        source_root: str = "tagged-source",
        extra_environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run the real publisher while routing every side effect to local doubles."""

        environment = os.environ.copy()
        environment.pop("CARGO_REGISTRY_TOKEN", None)
        environment.update(
            {
                "PATH": f"{self.bin}:{environment['PATH']}",
                "CRATES_IO_API_BASE": f"http://127.0.0.1:{self.server.server_port}",
                "CRATES_IO_POLL_INITIAL_SECONDS": "0.01",
                "CRATES_IO_POLL_MAX_SECONDS": "0.02",
                "CRATES_IO_POLL_TIMEOUT_SECONDS": "0.25",
                "PACKAGE_BUILD_JOBS": "1",
                "TEST_CRATE_VERSION": VERSION,
                "TEST_EXPECTED_REGISTRY_TOKEN": SECRET,
                "TMPDIR": str(self.root / "tmp"),
                "TEST_SOURCE_ROOT": str(self.source),
                "POISON_MARKER": str(self.poison_marker),
                "SLEEP_MARKER": str(self.sleep_marker),
            }
        )
        if extra_environment:
            environment.update(extra_environment)
        if include_token:
            environment["CARGO_REGISTRY_TOKEN"] = SECRET
        result = subprocess.run(
            [
                "bash",
                "automation/scripts/publish.sh",
                "--source-root",
                source_root,
            ],
            cwd=self.root,
            env=environment,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if self.poison_marker.exists():
            self.fail("publisher from the tagged source checkout was executed")
        return result

    def assert_secret_absent(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertNotIn(SECRET, result.stdout)
        self.assertNotIn(SECRET, result.stderr)

    def test_first_run_publishes_five_crates_in_dependency_order(self) -> None:
        """Locks out unsafe order, incomplete truth, or automation-manifest packaging."""

        missing_token = self.run_publish(include_token=False)
        self.assertEqual(missing_token.returncode, 2)
        self.assertIn("CARGO_REGISTRY_TOKEN is required", missing_token.stderr)
        self.assertEqual(self.state.publish_order, [])
        self.assert_secret_absent(missing_token)

        overlapping_root = self.run_publish(source_root="automation")
        self.assertEqual(overlapping_root.returncode, 2)
        self.assertIn("separate, non-overlapping checkout", overlapping_root.stderr)
        self.assertEqual(self.state.publish_order, [])
        self.assert_secret_absent(overlapping_root)

        dirty_marker = self.source / "dirty-marker"
        dirty_marker.write_text("not part of the tag", encoding="utf-8")
        dirty_source = self.run_publish()
        self.assertNotEqual(dirty_source.returncode, 0)
        self.assertIn("dirty working tree", dirty_source.stderr)
        self.assertEqual(self.state.publish_order, [])
        self.assert_secret_absent(dirty_source)
        dirty_marker.unlink()

        result = self.run_publish()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.state.publish_order, CRATES)
        self.assertEqual(list(self.state.archives), CRATES)
        self.assertEqual(
            self.state.poll_requests,
            {crate: 1 for crate in CRATES},
        )
        self.assertEqual(
            self.state.poll_authorizations,
            [None] * len(CRATES),
        )
        self.assertFalse(self.sleep_marker.exists())
        self.assertIn(f"All v{VERSION} crates published", result.stdout)
        self.assertNotIn("99.0.0", result.stdout + result.stderr)
        gate_calls = [json.loads(line) for line in self.gate_log.read_text().splitlines()]
        final = next(args for args in gate_calls if "--require-all-archives" in args)
        self.assertEqual([Path(value).name for value in final[1:]], [f"{crate}-{VERSION}.crate" for crate in CRATES])
        self.assert_secret_absent(result)

    def test_rerun_verifies_remote_archives_without_republishing(self) -> None:
        """Locks out relying on Cargo error text after a partial or complete run."""

        self.state.archives = {crate: crate_archive(crate) for crate in CRATES}

        result = self.run_publish()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.state.publish_order, [])
        self.assertEqual(result.stdout.count("verified without republishing"), len(CRATES))
        self.assertEqual(self.state.poll_requests, {})
        self.assertFalse(self.sleep_marker.exists())
        self.assert_secret_absent(result)

    def test_poll_retries_404_until_exact_version_is_visible(self) -> None:
        """Dependency tiers advance on visibility rather than a fixed delay."""

        self.state.visibility_404s["keyhog-core"] = 2

        result = self.run_publish()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.state.poll_requests["keyhog-core"], 3)
        self.assertIn(
            f"keyhog-core {VERSION} visible on crates.io after 3 attempt(s)",
            result.stderr,
        )
        self.assertEqual(self.state.publish_order, CRATES)
        self.assertFalse(self.sleep_marker.exists())
        self.assert_secret_absent(result)

    def test_poll_timeout_names_exact_version_endpoint_and_remediation(self) -> None:
        """A version that never appears stops dependent publication loudly."""

        self.state.permanent_404_for = "keyhog-core"

        result = self.run_publish(
            extra_environment={
                "CRATES_IO_POLL_INITIAL_SECONDS": "1",
                "CRATES_IO_POLL_MAX_SECONDS": "1",
                "CRATES_IO_POLL_TIMEOUT_SECONDS": "0.05",
            }
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.state.publish_order, ["keyhog-core"])
        self.assertEqual(self.state.poll_requests["keyhog-core"], 1)
        self.assertIn(f"waiting for keyhog-core {VERSION}", result.stderr)
        self.assertIn(
            f"/api/v1/crates/keyhog-core/{VERSION}",
            result.stderr,
        )
        self.assertIn("Remediation:", result.stderr)
        self.assertNotIn("keyhog-verifier published", result.stdout)
        self.assertFalse(self.sleep_marker.exists())
        self.assert_secret_absent(result)

    def test_poll_transport_error_is_loud_and_does_not_retry(self) -> None:
        """Transport failures are distinct from an unpublished-version 404."""

        self.state.transport_error_for = "keyhog-core"

        result = self.run_publish()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.state.publish_order, ["keyhog-core"])
        self.assertEqual(self.state.poll_requests["keyhog-core"], 1)
        self.assertIn("visibility check failed", result.stderr)
        self.assertIn(f"keyhog-core {VERSION}", result.stderr)
        self.assertIn(
            f"/api/v1/crates/keyhog-core/{VERSION}",
            result.stderr,
        )
        self.assertIn("Remediation:", result.stderr)
        self.assertNotIn("keyhog-verifier published", result.stdout)
        self.assertFalse(self.sleep_marker.exists())
        self.assert_secret_absent(result)

    def test_poll_configuration_rejects_unsafe_numbers_before_publication(self) -> None:
        """Intervals must be finite positive decimals in a coherent range."""

        for variable, value in (
            ("CRATES_IO_POLL_INITIAL_SECONDS", "0"),
            ("CRATES_IO_POLL_MAX_SECONDS", "nan"),
            ("CRATES_IO_POLL_TIMEOUT_SECONDS", "not-a-number"),
            ("CRATES_IO_POLL_INITIAL_SECONDS", "1e999999"),
            ("CRATES_IO_POLL_TIMEOUT_SECONDS", "1e-999999"),
        ):
            with self.subTest(variable=variable):
                result = self.run_publish(extra_environment={variable: value})
                self.assertEqual(result.returncode, 1)
                self.assertIn(variable, result.stderr)
                self.assertIn("positive finite decimal", result.stderr)
                self.assertEqual(self.state.publish_order, [])
                self.assert_secret_absent(result)

        result = self.run_publish(
            extra_environment={
                "CRATES_IO_POLL_INITIAL_SECONDS": "2",
                "CRATES_IO_POLL_MAX_SECONDS": "1",
            }
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "CRATES_IO_POLL_MAX_SECONDS must be greater than or equal",
            result.stderr,
        )
        self.assertEqual(self.state.publish_order, [])
        self.assert_secret_absent(result)

    def test_rerun_rejects_registry_archive_unlike_tagged_source(self) -> None:
        """Locks out treating a valid remote checksum as proof of tagged source bytes."""

        self.state.archives = {crate: crate_archive(crate) for crate in CRATES}
        self.state.archives["keyhog-core"] += b"remote-only-byte-drift"

        result = self.run_publish()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.state.publish_order, [])
        self.assertIn(
            "tagged source archive for already-published keyhog-core differs",
            result.stderr,
        )
        self.assert_secret_absent(result)

    def test_registry_byte_drift_fails_after_upload(self) -> None:
        """Locks out claiming success when crates.io records bytes unlike the package."""

        self.state.corrupt_upload_for = "keyhog-core"

        result = self.run_publish()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.state.publish_order, ["keyhog-core"])
        self.assertIn("crates.io checksum does not match", result.stderr)
        self.assertNotIn("keyhog-verifier published", result.stdout)
        self.assert_secret_absent(result)


if __name__ == "__main__":
    unittest.main()
