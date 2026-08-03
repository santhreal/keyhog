"""Behavioral regressions for deterministic release integrity receipts."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from scripts import release_integrity_receipt as receipt


class ReleaseIntegrityReceiptTests(unittest.TestCase):
    """Prove receipts bind every publishable crate to one source revision."""

    def make_workspace(self, root: Path, version: str = "0.5.50") -> bytes:
        """Create the smallest six-crate lock state accepted by the generator."""
        (root / "Cargo.toml").write_text(
            f'[workspace.package]\nversion = "{version}"\n', encoding="utf-8"
        )
        lock = "version = 4\n\n" + "".join(
            f'[[package]]\nname = "{name}"\nversion = "{version}"\n\n'
            for name in receipt.CRATES
        )
        lock_bytes = lock.encode()
        (root / "Cargo.lock").write_bytes(lock_bytes)
        return lock_bytes

    def test_receipt_is_byte_stable_and_preserves_dependency_publication_order(self) -> None:
        """The same release state must produce identical bytes and the six-crate dependency order."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = self.make_workspace(root)
            commit = "0123456789abcdef0123456789abcdef01234567"

            first = receipt.render_receipt(receipt.build_receipt(root, commit))
            second = receipt.render_receipt(receipt.build_receipt(root, commit, "0.5.50"))

            self.assertEqual(first, second)
            parsed = receipt.build_receipt(root, commit)
            self.assertEqual(
                [item["name"] for item in parsed["crates"]], list(receipt.CRATES)
            )
            self.assertEqual(
                [item["publish_order"] for item in parsed["crates"]],
                [1, 2, 3, 4, 5, 6],
            )
            self.assertEqual(parsed["cargo_lock_sha256"], hashlib.sha256(lock).hexdigest())
            self.assertEqual(parsed["tag"], "v0.5.50")

    def test_version_or_lock_drift_fails_before_a_receipt_can_claim_integrity(self) -> None:
        """A split workspace release must fail closed instead of issuing a misleading receipt."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_workspace(root)
            lock = (root / "Cargo.lock").read_text(encoding="utf-8")
            (root / "Cargo.lock").write_text(
                lock.replace(
                    'name = "keyhog-scanner"\nversion = "0.5.50"',
                    'name = "keyhog-scanner"\nversion = "0.5.49"',
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(receipt.ReceiptError, "keyhog-scanner=0.5.49"):
                receipt.build_receipt(
                    root, "0123456789abcdef0123456789abcdef01234567"
                )
            with self.assertRaisesRegex(receipt.ReceiptError, "does not match"):
                receipt.build_receipt(
                    root,
                    "0123456789abcdef0123456789abcdef01234567",
                    "0.5.51",
                )

    def test_invalid_commit_and_incomplete_lock_are_rejected(self) -> None:
        """Receipts must not accept abbreviated revisions or omit a published crate."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_workspace(root)
            with self.assertRaisesRegex(receipt.ReceiptError, "40-character"):
                receipt.build_receipt(root, "deadbeef")

            lock = (root / "Cargo.lock").read_text(encoding="utf-8")
            marker = '[[package]]\nname = "keyhog"\nversion = "0.5.50"\n\n'
            (root / "Cargo.lock").write_text(lock.replace(marker, ""), encoding="utf-8")
            with self.assertRaisesRegex(receipt.ReceiptError, "keyhog"):
                receipt.build_receipt(
                    root, "0123456789abcdef0123456789abcdef01234567"
                )

    def test_atomic_write_replaces_existing_output_with_exact_rendered_bytes(self) -> None:
        """Interrupted or repeated release runs must leave one complete canonical JSON document."""
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "nested" / "receipt.json"
            receipt.write_atomic(output, "first\n")
            receipt.write_atomic(output, "second\n")
            self.assertEqual(output.read_bytes(), b"second\n")
            self.assertEqual(list(output.parent.glob(f".{output.name}.*")), [])


if __name__ == "__main__":
    unittest.main()
