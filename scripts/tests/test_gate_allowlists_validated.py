import unittest

from scripts.gates import gate_allowlists_validated


class GateAllowlistsValidatedTests(unittest.TestCase):
    def test_valid_gate_source_passes(self) -> None:
        source = """
ALLOWED: dict[str, str] = {
    "crates/scanner/src/lib.rs": "canonical lib entrypoint",
}

def validate_allowlists():
    for path in ALLOWED:
        if not path.exists():
            raise ValueError("missing")
"""
        violations = gate_allowlists_validated.inspect_gate_source(source, "valid_gate.py")
        self.assertEqual(violations, [])

    def test_unvalidated_allowlist_is_rejected(self) -> None:
        source = """
ALLOWED = {
    "crates/scanner/src/lib.rs",
    "some/retired/file.rs",
}

def run_gate():
    for f in ALLOWED:
        print(f)
"""
        violations = gate_allowlists_validated.inspect_gate_source(source, "unvalidated_gate.py")
        self.assertEqual(len(violations), 1)
        self.assertIn("Defines allowlist variables", violations[0])

    def test_live_gate_suite_has_no_unvalidated_allowlists(self) -> None:
        violations = gate_allowlists_validated.audit_gates_suite()
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
