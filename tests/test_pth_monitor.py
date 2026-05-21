import io
import shutil
import unittest
import uuid
from contextlib import contextmanager
from pathlib import Path

from spip import Severity
from spip.pth_monitor import (
    PthMonitor,
    find_import_lines,
    handle_suspicious_pth_alerts,
    resolve_watch_directories,
)

TMP_ROOT = Path(".tmp-tests")
TMP_ROOT.mkdir(exist_ok=True)


@contextmanager
def temporary_workspace_dir():
    path = TMP_ROOT / f"tmp-{uuid.uuid4().hex}"
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


class FlushingStringIO(io.StringIO):
    def __init__(self) -> None:
        super().__init__()
        self.flush_calls = 0

    def flush(self) -> None:
        self.flush_calls += 1
        super().flush()


class PthMonitorTests(unittest.TestCase):
    def test_monitor_detects_new_import_pth(self) -> None:
        with temporary_workspace_dir() as site_packages:
            monitor = PthMonitor(directories=(site_packages,), snapshot={})
            suspicious = site_packages / "evil.pth"
            suspicious.write_text("import os\n", encoding="utf-8")

            alerts = monitor.inspect()

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, Severity.MEDIUM)
        self.assertEqual(alerts[0].path.name, "evil.pth")

    def test_monitor_ignores_non_import_pth(self) -> None:
        with temporary_workspace_dir() as site_packages:
            monitor = PthMonitor(directories=(site_packages,), snapshot={})
            harmless = site_packages / "harmless.pth"
            harmless.write_text("some_package\n", encoding="utf-8")

            alerts = monitor.inspect()

        self.assertEqual(alerts, [])

    def test_monitor_ignores_unchanged_existing_pth(self) -> None:
        with temporary_workspace_dir() as site_packages:
            existing = site_packages / "existing.pth"
            existing.write_text("import sys\n", encoding="utf-8")
            monitor = PthMonitor.from_install_args(["--target", str(site_packages)])

            alerts = monitor.inspect()

        self.assertEqual(alerts, [])

    def test_find_import_lines_returns_only_import_statements(self) -> None:
        with temporary_workspace_dir() as tmp:
            path = tmp / "sample.pth"
            path.write_text("pkg\n  import os\nimport sys\n", encoding="utf-8")

            lines = find_import_lines(path)

        self.assertEqual(lines, ["import os", "import sys"])

    def test_handle_alerts_deletes_pth_on_yes(self) -> None:
        with temporary_workspace_dir() as tmp:
            path = tmp / "evil.pth"
            path.write_text("import os\n", encoding="utf-8")
            alert = _alert_for(path)
            stderr = FlushingStringIO()
            stdin = io.StringIO("y\n")

            decision = handle_suspicious_pth_alerts(
                [alert],
                ignore_warning=False,
                stdin=stdin,
                stderr=stderr,
                is_tty=lambda: True,
            )

        self.assertTrue(decision.allow_install)
        self.assertEqual(decision.exit_code, 0)
        self.assertFalse(path.exists())
        self.assertIn("delete suspicious .pth file(s)? enter y/n [y/N]:", stderr.getvalue())
        self.assertIn("deleted 1 suspicious .pth file(s).", stderr.getvalue())
        self.assertIn("\x1b[", stderr.getvalue())
        self.assertEqual(stderr.flush_calls, 1)
        self.assertIn(f"path: {path}", stderr.getvalue())

    def test_handle_alerts_keeps_pth_on_no(self) -> None:
        with temporary_workspace_dir() as tmp:
            path = tmp / "evil.pth"
            path.write_text("import os\n", encoding="utf-8")
            alert = _alert_for(path)
            stderr = io.StringIO()
            stdin = io.StringIO("n\n")

            decision = handle_suspicious_pth_alerts(
                [alert],
                ignore_warning=False,
                stdin=stdin,
                stderr=stderr,
                is_tty=lambda: True,
            )

            exists_after = path.exists()

        self.assertTrue(decision.allow_install)
        self.assertEqual(decision.exit_code, 0)
        self.assertTrue(exists_after)
        self.assertIn("keeping suspicious .pth file(s).", stderr.getvalue())

    def test_handle_alerts_blocks_in_non_interactive_mode(self) -> None:
        with temporary_workspace_dir() as tmp:
            path = tmp / "evil.pth"
            path.write_text("import os\n", encoding="utf-8")
            alert = _alert_for(path)
            stderr = io.StringIO()

            decision = handle_suspicious_pth_alerts(
                [alert],
                ignore_warning=False,
                stderr=stderr,
                is_tty=lambda: False,
            )

        self.assertFalse(decision.allow_install)
        self.assertEqual(decision.exit_code, 2)
        self.assertIn("installation completed, but suspicious .pth files were found.", stderr.getvalue())
        self.assertIn("\x1b[", stderr.getvalue())

    def test_handle_alerts_ignore_warning_skips_prompt(self) -> None:
        with temporary_workspace_dir() as tmp:
            path = tmp / "evil.pth"
            path.write_text("import os\n", encoding="utf-8")
            alert = _alert_for(path)
            stderr = io.StringIO()

            decision = handle_suspicious_pth_alerts([alert], ignore_warning=True, stderr=stderr)
            exists_after = path.exists()

        self.assertTrue(decision.allow_install)
        self.assertEqual(decision.exit_code, 0)
        self.assertTrue(exists_after)

    def test_resolve_watch_directories_prefers_target(self) -> None:
        directories = resolve_watch_directories(["--target", "vendor"])
        self.assertEqual(directories, [Path("vendor").resolve()])

    def test_rendered_alert_includes_pth_path(self) -> None:
        with temporary_workspace_dir() as tmp:
            path = tmp / "evil.pth"
            alert = _alert_for(path)

            from spip.pth_monitor import render_suspicious_pth_alerts

            rendered = render_suspicious_pth_alerts([alert])

        self.assertIn(f"path: {path}", rendered)


def _alert_for(path: Path):
    from spip.pth_monitor import SuspiciousPthAlert

    return SuspiciousPthAlert(
        severity=Severity.MEDIUM,
        path=path,
        import_lines=("import os",),
        message=f"'{path}' contains executable import statements in a .pth file",
        remediation="review and delete the .pth file if it is not expected",
    )


if __name__ == "__main__":
    unittest.main()
