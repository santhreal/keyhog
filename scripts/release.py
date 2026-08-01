#!/usr/bin/env python3
"""Run KeyHog's complete local or SSH release workflow."""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import os
import re
import shlex
import subprocess
import time
import tomllib
from pathlib import Path
from typing import Callable

try:
    from scripts.prepare_release import CRATE_CHANGELOGS, VERSIONED_FILES, parse_version
except ModuleNotFoundError:
    from prepare_release import CRATE_CHANGELOGS, VERSIONED_FILES, parse_version

REPOSITORY = "https://github.com/santhreal/keyhog.git"
GITHUB_ACTOR_ID = "64453045"
_SSH_TARGET_RE = re.compile(
    r"^(?:[A-Za-z0-9_][A-Za-z0-9_.-]*@)?[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?$"
)
METRIC_PATHS = {Path("metrics/stars.json"), Path("metrics/stars.svg")}

DEFAULT_RELEASE_GNUPGHOME = Path("/credentials/keyhog-release-gnupg")
DEFAULT_RELEASE_GPG_PASSPHRASE_FILE = Path(
    "/credentials/keyhog-release-gpg-passphrase"
)


def release_gpg_environment() -> dict[str, str]:
    """Use the dedicated release keyring when this host has one."""
    configured = os.environ.get("KEYHOG_RELEASE_GNUPGHOME")
    home = Path(configured) if configured else DEFAULT_RELEASE_GNUPGHOME
    return {"GNUPGHOME": str(home)} if home.is_dir() else {}


def release_passphrase_file() -> Path | None:
    """Return the protected noninteractive passphrase file when configured."""
    configured = os.environ.get("KEYHOG_RELEASE_GPG_PASSPHRASE_FILE")
    path = Path(configured) if configured else DEFAULT_RELEASE_GPG_PASSPHRASE_FILE
    return path if path.is_file() else None


class ReleaseError(RuntimeError):
    """The release cannot continue without violating a publication invariant."""


class Runner:
    """Execute visible, argument-safe child processes from one repository root."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def run(
        self,
        args: list[str],
        *,
        env: dict[str, str] | None = None,
        check: bool = True,
        capture: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        print(f"$ {shlex.join(args)}", flush=True)
        process_env = os.environ.copy()
        if env:
            process_env.update(env)
        result = subprocess.run(
            args,
            cwd=self.root,
            env=process_env,
            text=True,
            check=False,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
        )
        if check and result.returncode != 0:
            detail = ""
            if capture:
                detail = (result.stderr or result.stdout or "").strip()
            raise ReleaseError(
                f"command exited {result.returncode}: {shlex.join(args)}"
                + (f"\n{detail}" if detail else "")
            )
        return result

    def output(self, args: list[str]) -> str:
        """Run one command and return stripped stdout."""
        return self.run(args, capture=True).stdout.strip()


@dataclasses.dataclass(frozen=True)
class Options:
    """Validated release orchestration choices."""

    version: str
    date: str
    publish: bool
    skip_benchmarks: bool
    skip_rust: bool
    watch: bool
    resume: bool = False

    @property
    def tag(self) -> str:
        return f"v{self.version}"


def validate_options(options: Options) -> None:
    """Reject ambiguous release identities before any subprocess runs."""
    parse_version(options.version)
    try:
        dt.date.fromisoformat(options.date)
    except ValueError as error:
        raise ReleaseError(f"invalid release date {options.date!r}") from error


def workspace_version(runner: Runner) -> str:
    """Read the exact workspace version that release preparation owns."""
    manifest = tomllib.loads((runner.root / "Cargo.toml").read_text(encoding="utf-8"))
    try:
        version = manifest["workspace"]["package"]["version"]
    except (KeyError, TypeError) as error:
        raise ReleaseError("Cargo.toml has no workspace.package.version") from error
    parse_version(version)
    return version


def remote_command(
    script_args: list[str], target: str, remote_dir: str, port: int | None, identity: str | None
) -> list[str]:
    """Build one quoted SSH invocation that cannot recursively dispatch."""
    if not _SSH_TARGET_RE.fullmatch(target):
        raise ReleaseError(
            "--ssh accepts only a host or user@host target without shell syntax"
        )
    if not remote_dir.startswith("/") or "\n" in remote_dir or "\r" in remote_dir:
        raise ReleaseError("--remote-dir must be one absolute remote path")
    command = ["ssh"]
    if port is not None:
        if not 1 <= port <= 65535:
            raise ReleaseError("--ssh-port must be between 1 and 65535")
        command.extend(("-p", str(port)))
    if identity is not None:
        command.extend(("-i", identity))
    command.append(target)
    remote = ["python3", "-B", "scripts/release.py", *script_args]
    command.append(
        f"cd -- {shlex.quote(remote_dir)} && exec {shlex.join(remote)}"
    )
    return command


def git_status_paths(runner: Runner) -> set[Path]:
    """Return every changed path without losing whitespace or quoted bytes."""
    result = runner.run(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        capture=True,
    )
    paths: set[Path] = set()
    for entry in result.stdout.split("\0"):
        if not entry:
            continue
        if len(entry) < 4 or entry[2] != " ":
            raise ReleaseError(f"cannot parse git status entry: {entry!r}")
        status, raw = entry[:2], entry[3:]
        if "R" in status or "C" in status:
            raise ReleaseError(
                f"release automation does not accept renamed paths: {entry!r}"
            )
        paths.add(Path(raw))
    return paths


def require_clean_main(runner: Runner, *, allow_local_ahead: bool = False) -> None:
    """Require a clean main checkout, allowing reviewed resume commits explicitly."""
    branch = runner.output(["git", "branch", "--show-current"])
    if branch != "main":
        raise ReleaseError(f"release must run from main, not {branch or 'detached HEAD'}")
    if git_status_paths(runner):
        raise ReleaseError("release requires a clean tree; commit change fragments first")
    remote = runner.output(["git", "remote", "get-url", "origin"])
    if remote != REPOSITORY:
        raise ReleaseError(f"origin must be {REPOSITORY}, got {remote}")
    runner.run(["git", "fetch", "origin", "main"])
    head = runner.output(["git", "rev-parse", "HEAD"])
    upstream = runner.output(["git", "rev-parse", "origin/main"])
    if head == upstream:
        return
    merge_base = runner.output(["git", "merge-base", "HEAD", "origin/main"])
    if allow_local_ahead and merge_base == upstream:
        return
    if allow_local_ahead and merge_base == head:
        changed = remote_only_paths(runner)
        if changed and changed <= METRIC_PATHS:
            return
    raise ReleaseError(
        "main must match origin/main; --resume accepts only clean release or metrics commits"
    )


def require_publication_identity(runner: Runner) -> str:
    """Bind local GitHub and signing credentials to the authorized maintainer."""
    runner.run(["gh", "auth", "status", "--hostname", "github.com"])
    actor_id = runner.output(["gh", "api", "user", "--jq", ".id | tostring"])
    if actor_id != GITHUB_ACTOR_ID:
        raise ReleaseError(
            f"active GitHub account actor ID {actor_id!r} is not authorized for KeyHog releases"
        )
    signing_key = runner.output(["git", "config", "--get", "user.signingkey"])
    if not signing_key:
        raise ReleaseError("git user.signingkey must name the authorized release key")
    signing_format = runner.run(
        ["git", "config", "--get", "gpg.format"], check=False, capture=True
    ).stdout.strip()
    if signing_format not in ("", "openpgp"):
        raise ReleaseError("release tags require an OpenPGP signing key")
    key_details = runner.run(
        [
            "gpg",
            "--batch",
            "--with-colons",
            "--fingerprint",
            "--fingerprint",
            "--list-secret-keys",
            signing_key,
        ],
        env=release_gpg_environment(),
        capture=True,
    ).stdout.strip()
    saw_secret_key = False
    for line in key_details.splitlines():
        fields = line.split(":")
        if fields[0] == "sec":
            saw_secret_key = True
        elif saw_secret_key and fields[0] == "fpr" and len(fields) > 9 and fields[9]:
            return fields[9].upper()
    raise ReleaseError(
        f"git user.signingkey {signing_key!r} has no usable OpenPGP secret-key fingerprint"
    )


def verify_tag_signature(runner: Runner, tag: str, expected_fingerprint: str) -> None:
    """Require one valid tag signature from the configured primary OpenPGP key."""
    result = runner.run(
        ["git", "verify-tag", "--raw", tag],
        env=release_gpg_environment(),
        check=False,
        capture=True,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise ReleaseError(
            f"tag {tag} does not have a valid OpenPGP signature"
            + (f": {detail}" if detail else "")
        )
    valid_fingerprints: set[str] = set()
    marker = "[GNUPG:] VALIDSIG "
    for line in (result.stderr + "\n" + result.stdout).splitlines():
        if marker not in line:
            continue
        fields = line.partition(marker)[2].split()
        if fields:
            valid_fingerprints.add(fields[0].upper())
            valid_fingerprints.add(fields[-1].upper())
    if expected_fingerprint.upper() not in valid_fingerprints:
        raise ReleaseError(
            f"tag {tag} was not signed by configured OpenPGP key "
            f"{expected_fingerprint.upper()}"
        )


def release_tag_state(runner: Runner, tag: str) -> tuple[str | None, bool]:
    """Return the peeled tag commit and whether the exact annotated tag is remote."""
    local = runner.run(
        ["git", "rev-parse", "-q", "--verify", f"refs/tags/{tag}^{{}}"],
        check=False,
        capture=True,
    )
    if local.returncode not in (0, 1):
        raise ReleaseError(f"cannot inspect local tag {tag}")
    local_commit = local.stdout.strip() if local.returncode == 0 else None
    remote = runner.run(
        [
            "git",
            "ls-remote",
            "--exit-code",
            "--tags",
            "origin",
            f"refs/tags/{tag}",
            f"refs/tags/{tag}^{{}}",
        ],
        check=False,
        capture=True,
    )
    if remote.returncode not in (0, 2):
        raise ReleaseError(f"cannot inspect remote tag {tag}")
    remote_commit: str | None = None
    if remote.returncode == 0:
        for line in remote.stdout.splitlines():
            commit, ref = line.split(maxsplit=1)
            if ref == f"refs/tags/{tag}^{{}}":
                remote_commit = commit
        if remote_commit is None:
            raise ReleaseError(f"remote tag {tag} is not an annotated tag")
    if local_commit and remote_commit and local_commit != remote_commit:
        raise ReleaseError(f"local and remote {tag} tags resolve to different commits")
    if remote_commit and not local_commit:
        runner.run(["git", "fetch", "origin", f"refs/tags/{tag}:refs/tags/{tag}"])
        local_commit = runner.output(
            ["git", "rev-parse", "--verify", f"refs/tags/{tag}^{{}}"]
        )
        if local_commit != remote_commit:
            raise ReleaseError(f"fetched tag {tag} does not match its remote commit")
    return local_commit, remote_commit is not None


def commit_expected(
    runner: Runner,
    message: str,
    allowed: Callable[[Path], bool],
) -> bool:
    """Commit only paths owned by one generated release phase."""
    changed = git_status_paths(runner)
    if not changed:
        print(f"No changes for {message}")
        return False
    unexpected = sorted(str(path) for path in changed if not allowed(path))
    if unexpected:
        raise ReleaseError(
            f"{message} changed unexpected paths: {', '.join(unexpected)}"
        )
    runner.run(["git", "add", "--", *sorted(str(path) for path in changed)])
    runner.run(["git", "commit", "-m", message])
    return True


def benchmark_path(path: Path) -> bool:
    """Return whether a path is generated benchmark or star-viewer evidence."""
    return (
        path == Path("README.md")
        or path == Path("metrics/stars.svg")
        or path == Path("benchmarks/run-sets/canonical.toml")
        or Path("benchmarks/reports") in path.parents
    )


def release_path(path: Path) -> bool:
    """Return whether the deterministic release preparer owns a path."""
    static = {
        Path("Cargo.toml"),
        Path("Cargo.lock"),
        Path("CHANGELOG.md"),
        *VERSIONED_FILES,
        *CRATE_CHANGELOGS.values(),
    }
    return path in static or (
        Path("changes") in path.parents and path.suffix == ".toml"
    )


def candidate_binary() -> Path:
    """Resolve the immutable local benchmark candidate path."""
    target = Path(
        os.environ.get(
            "CARGO_TARGET_DIR", "/mnt/FlareTraining/santh-archive/cargo-target"
        )
    )
    return target / "release-fast" / "keyhog"

def release_proof_binary() -> Path:
    """Resolve the immutable default-feature candidate copied by prerelease."""
    return candidate_binary().with_name("keyhog-release-candidate")



def refresh_benchmarks(runner: Runner, options: Options) -> None:
    """Regenerate every committed README benchmark panel from one candidate."""
    candidate = candidate_binary()
    runner.run(
        ["cargo", "build", "-p", "keyhog", "--bin", "keyhog", "--profile", "release-fast"]
    )
    if not candidate.is_file():
        raise ReleaseError(f"benchmark candidate was not built at {candidate}")
    make_env = {
        "KEYHOG_BIN": str(candidate),
        "KEYHOG_BENCH_ALLOW_GENERATED_EVIDENCE_DIRTY": "1",
    }
    runner.run(["make", "-C", "benchmarks", "mirror"], env=make_env)
    runner.run(["make", "-C", "benchmarks", "canonical"], env=make_env)
    runner.run(["make", "-C", "benchmarks", "report"], env=make_env)
    runner.run(
        [
            "make",
            "-C",
            "benchmarks",
            "readme-matrix",
            "README_MATRIX_SOURCE_STATE=developer-dirty",
            "README_SCALING_SOURCE_STATE=developer-dirty",
        ],
        env=make_env,
    )
    runner.run(["python3", "-B", "scripts/star_history.py"])
    runner.run(["make", "-C", "benchmarks", "report-check"], env=make_env)
    commit_expected(
        runner,
        f"bench: refresh {options.tag} release evidence",
        benchmark_path,
    )


def prepare_release(runner: Runner, options: Options) -> None:
    """Apply and commit the deterministic changelog and version transaction."""
    runner.run(
        [
            "make",
            "release-prepare",
            f"VERSION={options.version}",
            f"DATE={options.date}",
        ]
    )
    if not commit_expected(
        runner, f"release: prepare {options.tag}", release_path
    ):
        raise ReleaseError("release preparation produced no commit")


def run_pre_tag_gates(runner: Runner, options: Options) -> None:
    """Prove source behavior before creating the immutable signed tag."""
    command = ["scripts/prerelease.sh", "--pre-tag"]
    if options.skip_rust:
        command.append("--skip-rust")
    runner.run(command)
    runner.run(["make", "docs-build"])
    runner.run(
        ["bash", "scripts/gates/run_all.sh"],
        env={"KEYHOG_BIN": str(release_proof_binary())},
    )
    if git_status_paths(runner):
        raise ReleaseError("verification changed the committed release tree")


def remote_only_paths(runner: Runner) -> set[Path]:
    """Return paths changed only by commits currently on origin/main."""
    commits = runner.output(["git", "rev-list", "HEAD..origin/main"]).splitlines()
    paths: set[Path] = set()
    for commit in commits:
        output = runner.output(
            ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", commit]
        )
        paths.update(Path(line) for line in output.splitlines() if line)
    return paths


def push_main(runner: Runner) -> None:
    """Push main, rebasing only over isolated star-history automation races."""
    for attempt in range(1, 4):
        runner.run(["git", "fetch", "origin", "main"])
        upstream = runner.output(["git", "rev-parse", "origin/main"])
        head = runner.output(["git", "rev-parse", "HEAD"])
        if upstream != head:
            merge_base = runner.output(["git", "merge-base", "HEAD", "origin/main"])
            if merge_base == head:
                changed = remote_only_paths(runner)
                if not changed or not changed <= METRIC_PATHS:
                    raise ReleaseError(
                        "origin/main advanced with non-metrics work; inspect and rerun the release"
                    )
                print("origin/main already contains the release commit plus metrics")
                return
            if merge_base != upstream:
                changed = remote_only_paths(runner)
                if not changed or not changed <= METRIC_PATHS:
                    raise ReleaseError(
                        "origin/main advanced with non-metrics work; inspect and rerun the release"
                    )
                runner.run(["git", "rebase", "origin/main"])
        result = runner.run(
            ["git", "push", "origin", "HEAD:main"], check=False, capture=True
        )
        if result.returncode == 0:
            print(result.stdout.strip())
            return
        if attempt == 3:
            raise ReleaseError(
                "main push raced three times:\n" + (result.stderr or result.stdout).strip()
            )
        time.sleep(attempt * 2)
    raise AssertionError("bounded push loop did not return")


def find_workflow_run(
    runner: Runner, workflow: str, commit: str, branch: str, timeout_seconds: int = 600
) -> int:
    """Wait until GitHub exposes one exact workflow run for the release commit."""
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        raw = runner.output(
            [
                "gh",
                "run",
                "list",
                "--workflow",
                workflow,
                "--branch",
                branch,
                "--commit",
                commit,
                "--limit",
                "20",
                "--json",
                "databaseId,headSha,status,conclusion",
            ]
        )
        runs = json.loads(raw)
        exact = [item for item in runs if item.get("headSha") == commit]
        if exact:
            return int(max(exact, key=lambda item: int(item["databaseId"]))["databaseId"])
        time.sleep(10)
    raise ReleaseError(
        f"GitHub did not expose {workflow} for {branch} at {commit} within {timeout_seconds}s"
    )


def watch_publication(runner: Runner, options: Options, commit: str) -> None:
    """Watch Pages and release publication, then verify the public release identity."""
    release_run = find_workflow_run(runner, "release.yml", commit, options.tag)
    runner.run(["gh", "run", "watch", str(release_run), "--exit-status"])
    docs_run = find_workflow_run(runner, "docs.yml", commit, "main")
    runner.run(["gh", "run", "watch", str(docs_run), "--exit-status"])
    raw = runner.output(
        [
            "gh",
            "release",
            "view",
            options.tag,
            "--json",
            "tagName,isDraft,isPrerelease,publishedAt,url",
        ]
    )
    release = json.loads(raw)
    expected_url = f"https://github.com/santhreal/keyhog/releases/tag/{options.tag}"
    if (
        release.get("tagName") != options.tag
        or release.get("isDraft") is not False
        or release.get("isPrerelease") is not False
        or not release.get("publishedAt")
        or release.get("url") != expected_url
    ):
        raise ReleaseError(f"published release identity is incomplete: {release}")
    print(f"Published {options.tag}: {release['url']}")
    print("The successful release workflow includes the serial crates.io publisher.")


def preview(runner: Runner, options: Options) -> None:
    """Run the read-only release transaction and display the publication phases."""
    runner.run(["python3", "-B", "scripts/star_history.py", "--check"])
    prepared = options.resume and workspace_version(runner) == options.version
    if not prepared:
        runner.run(
            [
                "make",
                "release-check",
                f"VERSION={options.version}",
                f"DATE={options.date}",
            ]
        )
    version_phase = (
        "Retain prepared changelogs and versions"
        if prepared
        else "Prepare and commit changelogs, versions, and documentation"
    )
    benchmark_phase = (
        "Retain previously checked benchmark evidence"
        if options.skip_benchmarks
        else "Refresh benchmark tables and repository star chart"
    )
    rust_scope = "excluding the diagnostic Rust rerun" if options.skip_rust else "including Rust"
    print("\nValidated release plan:")
    print(f"  1. {version_phase}")
    print(f"  2. {benchmark_phase}")
    print(f"  3. Run pre-tag source, benchmark, mdBook, and prevention gates, {rust_scope}")
    print("  4. Push main and one verified OpenPGP-signed annotated tag")
    print("  5. Watch GitHub release, Pages, GHCR, assets, and crates.io publication")
    print("Run again with --publish to execute these irreversible publication phases.")


def publish(runner: Runner, options: Options) -> None:
    """Execute or resume the complete reviewed release and publication workflow."""
    expected_fingerprint = require_publication_identity(runner)
    current = workspace_version(runner)
    current_key = parse_version(current)
    target_key = parse_version(options.version)
    tag_commit, tag_remote = release_tag_state(runner, options.tag)
    if tag_commit:
        verify_tag_signature(runner, options.tag, expected_fingerprint)
    if tag_commit and not options.resume:
        raise ReleaseError(f"tag {options.tag} already exists; use --resume to verify it")
    if current_key > target_key:
        raise ReleaseError(
            f"workspace version {current} is newer than requested {options.version}"
        )
    prepared = current_key == target_key
    if prepared and not options.resume:
        raise ReleaseError(
            f"workspace is already {options.version}; use --resume to continue publication"
        )
    if tag_commit and not prepared:
        raise ReleaseError(
            f"tag {options.tag} exists but workspace version is still {current}"
        )

    print("\n[1/5] Changelogs and versions")
    if prepared:
        print(f"Workspace and changelogs already identify {options.tag}.")
    else:
        prepare_release(runner, options)

    print("\n[2/5] Measured evidence")
    if tag_commit:
        print(f"Signed tag {options.tag} already exists; retaining its immutable evidence.")
    elif options.skip_benchmarks:
        print("Diagnostic override: retaining previously checked benchmark evidence.")
    else:
        refresh_benchmarks(runner, options)

    print("\n[3/5] Pre-tag proofs")
    if options.skip_rust:
        print("Diagnostic override: skipping the duplicate local Rust gate.")
    run_pre_tag_gates(runner, options)

    print("\n[4/5] Main branch and signed tag")
    push_main(runner)
    commit = runner.output(["git", "rev-parse", "HEAD"])
    if tag_commit:
        if tag_commit != commit:
            raise ReleaseError(
                f"existing {options.tag} resolves to {tag_commit}, not release commit {commit}"
            )
        if not tag_remote:
            runner.run(["git", "push", "origin", f"refs/tags/{options.tag}"])
    else:
        passphrase_file = release_passphrase_file()
        if passphrase_file is None:
            runner.run(
                ["git", "tag", "-s", "-a", options.tag, "-m", f"KeyHog {options.tag}"]
            )
        else:
            runner.run(
                [
                    "python3",
                    "-B",
                    "scripts/sign_release_tag.py",
                    "--tag",
                    options.tag,
                    "--commit",
                    commit,
                    "--fingerprint",
                    expected_fingerprint,
                    "--passphrase-file",
                    str(passphrase_file),
                ],
                env=release_gpg_environment(),
            )
        verify_tag_signature(runner, options.tag, expected_fingerprint)
        runner.run(["git", "push", "origin", f"refs/tags/{options.tag}"])

    print("\n[5/5] Publication verification")
    if options.watch:
        watch_publication(runner, options, commit)
    else:
        print(
            f"Pushed {options.tag}. Watch CI, Release, docs, and crates publication on GitHub."
        )


def parser() -> argparse.ArgumentParser:
    """Build the public command-line contract."""
    command = argparse.ArgumentParser(
        description=(
            "Preview or publish one complete KeyHog release locally or on an SSH host."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  scripts/release.py X.Y.Z
  scripts/release.py X.Y.Z --publish
  scripts/release.py X.Y.Z --ssh USER@HOST --remote-dir /srv/keyhog --publish
  scripts/release.py X.Y.Z --publish --resume""",
    )
    command.add_argument("version", help="next stable SemVer without a v prefix")
    command.add_argument(
        "--date",
        metavar="YYYY-MM-DD",
        default=dt.datetime.now(dt.UTC).date().isoformat(),
        help="release date in UTC; defaults to today",
    )
    command.add_argument(
        "--publish",
        action="store_true",
        help="commit, push, sign, tag, and start irreversible publication",
    )
    command.add_argument(
        "--skip-benchmarks",
        action="store_true",
        help="diagnostic override; retain already-checked benchmark evidence",
    )
    command.add_argument(
        "--skip-rust",
        action="store_true",
        help="diagnostic override; omit the duplicate local Rust gate",
    )
    command.add_argument(
        "--no-watch",
        action="store_true",
        help="return after tag push instead of watching exact publication workflows",
    )
    command.add_argument(
        "--resume",
        action="store_true",
        help="resume an already prepared commit or exact signed tag",
    )
    command.add_argument(
        "--ssh",
        metavar="USER@HOST",
        help="execute the same release command on one prepared SSH host",
    )
    command.add_argument(
        "--remote-dir",
        metavar="ABSOLUTE_PATH",
        help="absolute KeyHog checkout path on the SSH host",
    )
    command.add_argument(
        "--ssh-port",
        type=int,
        metavar="PORT",
        help="SSH port between 1 and 65535",
    )
    command.add_argument(
        "--identity-file",
        metavar="PATH",
        help="local SSH private-key path",
    )
    return command


def forwarded_args(args: argparse.Namespace) -> list[str]:
    """Serialize local release options for one remote invocation."""
    result = [args.version, "--date", args.date]
    if args.publish:
        result.append("--publish")
    if args.skip_benchmarks:
        result.append("--skip-benchmarks")
    if args.skip_rust:
        result.append("--skip-rust")
    if args.no_watch:
        result.append("--no-watch")
    if args.resume:
        result.append("--resume")
    return result


def main() -> int:
    args = parser().parse_args()
    if args.ssh:
        if not args.remote_dir:
            raise SystemExit("ERROR: --remote-dir is required with --ssh")
        command = remote_command(
            forwarded_args(args),
            args.ssh,
            args.remote_dir,
            args.ssh_port,
            args.identity_file,
        )
        raise SystemExit(subprocess.run(command, check=False).returncode)
    if args.remote_dir or args.ssh_port or args.identity_file:
        raise SystemExit("ERROR: remote options require --ssh")
    options = Options(
        version=args.version,
        date=args.date,
        publish=args.publish,
        skip_benchmarks=args.skip_benchmarks,
        skip_rust=args.skip_rust,
        watch=not args.no_watch,
        resume=args.resume,
    )
    try:
        validate_options(options)
        root = Path(__file__).resolve().parents[1]
        runner = Runner(root)
        require_clean_main(runner, allow_local_ahead=options.resume)
        if options.publish:
            publish(runner, options)
        else:
            preview(runner, options)
    except (OSError, ReleaseError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"ERROR: {error}") from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
