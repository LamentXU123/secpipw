import io
import unittest
from types import SimpleNamespace

from spip import Severity
from spip.warning_gate import enforce_warning_policy


class FlushingStringIO(io.StringIO):
    def __init__(self) -> None:
        super().__init__()
        self.flush_calls = 0

    def flush(self) -> None:
        self.flush_calls += 1
        super().flush()


class WarningGateTests(unittest.TestCase):
    def test_allows_when_no_warnings(self) -> None:
        decision = enforce_warning_policy([], ignore_warning=False)

        self.assertTrue(decision.allow_install)
        self.assertEqual(decision.exit_code, 0)

    def test_ignore_warning_bypasses_gate(self) -> None:
        warnings = [SimpleNamespace(severity=Severity.HIGH, message="high risk")]

        decision = enforce_warning_policy(warnings, ignore_warning=True)

        self.assertTrue(decision.allow_install)
        self.assertEqual(decision.exit_code, 0)

    def test_high_warning_blocks_and_instructs_ignore_flag(self) -> None:
        stderr = io.StringIO()
        warnings = [SimpleNamespace(severity=Severity.HIGH, message="high risk")]

        decision = enforce_warning_policy(warnings, ignore_warning=False, stderr=stderr)

        self.assertFalse(decision.allow_install)
        self.assertEqual(decision.exit_code, 2)
        self.assertIn("high severity warning detected", stderr.getvalue())
        self.assertIn("--ignore-warning", stderr.getvalue())
        self.assertIn("\x1b[", stderr.getvalue())

    def test_medium_warning_prompts_and_allows_on_yes(self) -> None:
        stderr = FlushingStringIO()
        stdin = io.StringIO("yes\n")
        warnings = [SimpleNamespace(severity=Severity.MEDIUM, message="medium risk")]

        decision = enforce_warning_policy(
            warnings,
            ignore_warning=False,
            stdin=stdin,
            stderr=stderr,
            is_tty=lambda: True,
        )

        self.assertTrue(decision.allow_install)
        self.assertEqual(decision.exit_code, 0)
        self.assertIn("continue install? enter y/n [y/N]:", stderr.getvalue())
        self.assertIn("\x1b[", stderr.getvalue())
        self.assertEqual(stderr.flush_calls, 1)

    def test_medium_warning_cancels_on_non_yes_answer(self) -> None:
        stderr = io.StringIO()
        stdin = io.StringIO("maybe\n")
        warnings = [SimpleNamespace(severity=Severity.MEDIUM, message="medium risk")]

        decision = enforce_warning_policy(
            warnings,
            ignore_warning=False,
            stdin=stdin,
            stderr=stderr,
            is_tty=lambda: True,
        )

        self.assertFalse(decision.allow_install)
        self.assertEqual(decision.exit_code, 1)
        self.assertIn("installation cancelled.", stderr.getvalue())

    def test_medium_warning_blocks_in_non_interactive_mode(self) -> None:
        stderr = io.StringIO()
        warnings = [SimpleNamespace(severity=Severity.MEDIUM, message="medium risk")]

        decision = enforce_warning_policy(
            warnings,
            ignore_warning=False,
            stderr=stderr,
            is_tty=lambda: False,
        )

        self.assertFalse(decision.allow_install)
        self.assertEqual(decision.exit_code, 2)
        self.assertIn("requires confirmation", stderr.getvalue())

    def test_low_warning_allows_install_without_prompt(self) -> None:
        stderr = io.StringIO()
        warnings = [SimpleNamespace(severity=Severity.LOW, message="low risk")]

        decision = enforce_warning_policy(
            warnings,
            ignore_warning=False,
            stderr=stderr,
            is_tty=lambda: True,
        )

        self.assertTrue(decision.allow_install)
        self.assertEqual(decision.exit_code, 0)
        self.assertEqual(stderr.getvalue(), "")

    def test_mixed_warnings_high_takes_precedence(self) -> None:
        stderr = io.StringIO()
        warnings = [
            SimpleNamespace(severity=Severity.LOW, message="low risk"),
            SimpleNamespace(severity=Severity.MEDIUM, message="medium risk"),
            SimpleNamespace(severity=Severity.HIGH, message="high risk"),
        ]

        decision = enforce_warning_policy(
            warnings,
            ignore_warning=False,
            stderr=stderr,
            is_tty=lambda: True,
        )

        self.assertFalse(decision.allow_install)
        self.assertEqual(decision.exit_code, 2)
        self.assertIn("high severity warning detected", stderr.getvalue())
        self.assertNotIn("continue install?", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
